# Комплексный набор тестов отказоустойчивости, контрактов и архитектурных инвариантов
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock
import httpx
import pytest
from epitaph.core.limiter import DomainRateLimiter
from epitaph.execution.checkers.github import GitHubChecker
from epitaph.execution.checkers.steam import SteamChecker
from epitaph.models.base import DetectionStatus, ExecutionType, ProxyProtocol
from epitaph.models.proxy import ProxyEntity
from epitaph.models.result import CheckResult, ScanSessionResult
from epitaph.models.target import TargetProfile
from epitaph.network.circuit_breaker import CircuitBreaker
from epitaph.network.proxy_manager import ProxyManager
from epitaph.reporting.dispatcher import ReportDispatcher, get_default_report_dir


@pytest.mark.asyncio
async def test_github_checker_network_timeout_handling() -> None:
    # Проверка изоляции таймаута без выброса необработанного исключения в планировщик
    checker = GitHubChecker()
    target = TargetProfile(username="octocat")

    mock_client = AsyncMock()
    mock_client.get.side_effect = httpx.ReadTimeout("Read connection timeout")

    result = await checker.check_http(target, mock_client)
    assert isinstance(result, CheckResult)
    assert result.status == DetectionStatus.ERROR
    assert result.platform_name == "GitHub"
    assert "Timeout" in (result.error_message or "")


@pytest.mark.asyncio
async def test_github_checker_unsupported_browser_execution() -> None:
    # Проверка возврата детерминированного CheckResult при вызове неподдерживаемого браузера
    checker = GitHubChecker()
    target = TargetProfile(username="octocat")

    result = await checker.check_browser(target, None)
    assert isinstance(result, CheckResult)
    assert result.status == DetectionStatus.ERROR
    assert result.error_message is not None


@pytest.mark.asyncio
async def test_steam_checker_unsupported_http_execution() -> None:
    # Проверка возврата статуса BLOCKED при вызове HTTP-метода для браузерного чекера
    checker = SteamChecker()
    target = TargetProfile(username="gaben")

    result = await checker.check_http(target, None)
    assert isinstance(result, CheckResult)
    assert result.status == DetectionStatus.BLOCKED
    assert result.error_message is not None


@pytest.mark.asyncio
async def test_domain_rate_limiter_interval() -> None:
    # Проверка соблюдения минимальной паузы между последовательными запросами к домену
    limiter = DomainRateLimiter()
    domain = "api.github.com"
    delay = 0.05

    t_start = asyncio.get_event_loop().time()
    await limiter.acquire(domain, delay)
    await limiter.acquire(domain, delay)
    t_elapsed = asyncio.get_event_loop().time() - t_start

    assert t_elapsed >= delay


@pytest.mark.asyncio
async def test_circuit_breaker_quarantine_transition() -> None:
    # Проверка перехода узла в карантин при превышении порога последовательных ошибок
    proxy = ProxyEntity(host="10.0.0.1", port=8080, protocol=ProxyProtocol.HTTP)
    breaker = CircuitBreaker(failure_threshold=2, cooldown_seconds=60)
    manager = ProxyManager(proxies=[proxy], circuit_breaker=breaker)

    leased = await manager.lease_proxy()
    assert leased is not None

    await manager.report_failure(leased)
    assert len(manager.active_proxies) == 1
    assert len(manager.quarantine_proxies) == 0

    await manager.report_failure(leased)
    assert len(manager.active_proxies) == 0
    assert len(manager.quarantine_proxies) == 1
    assert manager.quarantine_proxies[0].is_active is False
    assert manager.quarantine_proxies[0].cooldown_until is not None


def test_tmpdir_resolution_crossplatform(monkeypatch: pytest.MonkeyPatch) -> None:
    # Проверка формирования пути к отчетам с поддержкой каталога TMPDIR в Termux
    test_tmp_path = "/data/data/com.termux/files/usr/tmp"
    monkeypatch.setenv("TMPDIR", test_tmp_path)
    monkeypatch.setattr("epitaph.reporting.dispatcher.get_downloads_dir", lambda: None)

    report_dir = get_default_report_dir("sess_abc", "target_nick")
    assert str(report_dir).startswith(test_tmp_path)
    assert report_dir.name == "target_nick_sess_abc"


@pytest.mark.asyncio
async def test_report_dispatcher_export_formats(tmp_path: Path) -> None:
    # Проверка генерации всех заявленных форматов отчетов при валидных входных данных
    target = TargetProfile(username="test_user")
    now = datetime.now(timezone.utc)
    res = CheckResult(
        platform_name="GitHub",
        target=target,
        status=DetectionStatus.FOUND,
        profile_url="https://github.com/test_user",
        execution_type=ExecutionType.HTTP,
    )
    session = ScanSessionResult(
        session_id="test_sess",
        target=target,
        start_time=now,
        end_time=now,
        results=[res],
    )

    dispatcher = ReportDispatcher()
    generated = await dispatcher.export_all(session, tmp_path)

    for fmt in ("json", "txt", "html", "pdf"):
        assert fmt in generated
        assert generated[fmt].exists()
        assert generated[fmt].stat().st_size > 0


@pytest.mark.asyncio
async def test_html_report_export_termux_downloads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Проверка сохранения HTML-отчета напрямую в Downloads Termux и дублирования в сессию
    fake_downloads = tmp_path / "storage" / "downloads"
    fake_downloads.mkdir(parents=True)
    monkeypatch.setattr("epitaph.reporting.dispatcher.get_downloads_dir", lambda: fake_downloads)

    target = TargetProfile(username="termux_user")
    now = datetime.now(timezone.utc)
    res = CheckResult(
        platform_name="GitHub",
        target=target,
        status=DetectionStatus.FOUND,
        profile_url="https://github.com/termux_user",
        execution_type=ExecutionType.HTTP,
    )
    session = ScanSessionResult(
        session_id="termux_sess",
        target=target,
        start_time=now,
        end_time=now,
        results=[res],
    )

    dispatcher = ReportDispatcher()
    exported_html = await dispatcher.export_html(session)

    assert exported_html.exists()
    assert exported_html.parent == fake_downloads
    assert exported_html.name == "report_termux_user_termux_sess.html"

    backup_copy = fake_downloads / "Epitaph" / "reports" / "termux_user_termux_sess" / "report.html"
    assert backup_copy.exists()
    content = exported_html.read_text(encoding="utf-8")
    assert "viewport" in content
    assert "termux_user" in content


@pytest.mark.asyncio
async def test_html_report_export_termux_fallback_tmpdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Проверка гарантированного отката сохранения HTML в TMPDIR при отсутствии доступа к памяти
    fake_tmp = tmp_path / "usr_tmp"
    fake_tmp.mkdir(parents=True)
    monkeypatch.setenv("TMPDIR", str(fake_tmp))
    monkeypatch.setattr("epitaph.reporting.dispatcher.get_downloads_dir", lambda: None)

    target = TargetProfile(username="fallback_user")
    now = datetime.now(timezone.utc)
    session = ScanSessionResult(
        session_id="fb_sess",
        target=target,
        start_time=now,
        end_time=now,
        results=[],
    )

    dispatcher = ReportDispatcher()
    exported_html = await dispatcher.export_html(session)

    assert exported_html.exists()
    assert str(exported_html).startswith(str(fake_tmp))
    assert exported_html.name == "report.html"
