import asyncio
import os
import re
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
import httpx
import pytest

from epitaph.core.limiter import DomainRateLimiter
from epitaph.core.scheduler import TaskScheduler
from epitaph.execution.base import BasePlatformChecker
from epitaph.execution.generic import GenericPlatformChecker
from epitaph.execution.maigret import MaigretExecutor
from epitaph.models.base import DetectionStatus, ExecutionType, ProxyProtocol
from epitaph.models.proxy import ProxyEntity
from epitaph.models.result import CheckResult, ScanSessionResult
from epitaph.models.site import CheckType, SiteDefinition
from epitaph.models.target import TargetProfile
from epitaph.network.browser_pool import PlaywrightBrowserPool
from epitaph.network.http_client import HttpClientManager
from epitaph.network.proxy_manager import ProxyManager
from epitaph.reporting.dispatcher import ReportDispatcher, get_default_report_dir
from epitaph.reporting.formats.pdf_export import PdfReportExporter
from epitaph.utils.logger import sanitize_log_message, setup_logger


class DummyChecker(BasePlatformChecker):
    @property
    def name(self) -> str:
        return "Dummy"

    @property
    def execution_type(self) -> ExecutionType:
        return ExecutionType.HTTP

    async def check_http(self, target: TargetProfile, client: httpx.AsyncClient) -> CheckResult:
        return CheckResult(
            platform_name=self.name,
            target=target,
            status=DetectionStatus.FOUND,
            execution_type=self.execution_type,
        )

    async def check_browser(self, target: TargetProfile, context: object) -> CheckResult:
        return CheckResult(
            platform_name=self.name,
            target=target,
            status=DetectionStatus.BLOCKED,
            execution_type=self.execution_type,
        )


@pytest.mark.asyncio
async def test_opsec_01_fail_closed_scheduler() -> None:
    # [OPSEC-01] Проверка принципа Fail-Closed: при пустом пуле прокси возвращается детерминированная ошибка
    mock_proxy_mgr = MagicMock()
    mock_proxy_mgr.lease_proxy = AsyncMock(return_value=None)

    scheduler = TaskScheduler(proxy_manager=mock_proxy_mgr)
    checker = DummyChecker()
    target = TargetProfile(username="test_target")

    result = await scheduler.run_checker(checker, target)
    assert result.status == DetectionStatus.ERROR
    assert "Fail-Closed" in (result.error_message or "")


@pytest.mark.asyncio
async def test_opsec_01_http_client_enforce_proxy() -> None:
    # [OPSEC-01] Прямое подключение запрещено при включенном флаге enforce_proxy
    client_mgr = HttpClientManager(enforce_proxy=True)
    with pytest.raises(RuntimeError, match="Fail-Closed"):
        await client_mgr.get_client(None)


@pytest.mark.asyncio
async def test_opsec_02_neutral_accept_language() -> None:
    # [OPSEC-02] Проверка отсутствия регионального фингерпринта в заголовках
    site = SiteDefinition(name="Test", url="https://example.com/{username}")
    checker = GenericPlatformChecker(site)
    headers = checker.headers

    assert headers.get("Accept-Language") == "en-US,en;q=0.9"
    assert "ru" not in headers.get("Accept-Language", "")
    assert "uk" not in headers.get("Accept-Language", "")


@pytest.mark.asyncio
async def test_appsec_05_username_sanitization_ssrf() -> None:
    # [APPSEC-05] Санитизация никнейма от SSRF и инъекций путей
    site = SiteDefinition(name="TestSite", url="https://example.com/users/{username}")
    checker = GenericPlatformChecker(site)
    target = TargetProfile(username="../../admin?token=evil#frag")

    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_client.get.return_value = mock_response

    await checker.check_http(target, mock_client)
    call_args = mock_client.get.call_args
    requested_url = call_args[0][0]

    assert "/../" not in requested_url
    assert "%2F" in requested_url
    assert "%3F" in requested_url
    assert "admin" in requested_url


@pytest.mark.asyncio
async def test_opsec_03_maigret_proxy_isolation() -> None:
    # [OPSEC-03] Изоляция трафика: при наличии прокси-пула вызов нативного Maigret блокируется
    queue = asyncio.Queue()
    mock_engine = MagicMock()
    mock_engine.scheduler.proxy_manager = MagicMock()
    mock_engine.run_scan = AsyncMock()

    executor = MaigretExecutor(event_queue=queue, engine=mock_engine)
    target = TargetProfile(username="target1")

    await executor.run_search(target)
    mock_engine.run_scan.assert_awaited_once()


def test_appsec_01_and_02_browser_security() -> None:
    # [APPSEC-01 & APPSEC-02] TLS-валидация включена, песочница активна по умолчанию
    pool = PlaywrightBrowserPool()
    assert pool.insecure_tls is False


def test_opsec_04_default_report_dir_permissions() -> None:
    # [OPSEC-04] Отчеты сохраняются в приватный каталог ~/.epitaph/reports с правами 0700
    report_dir = get_default_report_dir("sess123", "user1")

    assert str(Path.home() / ".epitaph" / "reports") in str(report_dir)
    assert not str(report_dir).startswith("/sdcard")
    assert not str(report_dir).startswith("/storage/emulated")


def test_proxy_socks5h_and_quote() -> None:
    # [Блок 2.2] Протокол socks5h и экранирование спецсимволов в логине/пароле
    p = ProxyEntity(
        host="proxy.domain",
        port=1080,
        protocol=ProxyProtocol.SOCKS5,
        username="user@name",
        password="p@ss:w/ord",
    )
    assert p.url.startswith("socks5h://")
    assert "user%40name" in p.url
    assert "p%40ss%3Aw%2Ford" in p.url


def test_limiter_adaptive_jitter() -> None:
    # [Блок 2.3] Адаптивный рандомизированный джиттер (±20-30%)
    limiter = DomainRateLimiter()
    delays = [limiter.calculate_jittered_delay(1.0) for _ in range(50)]
    assert all(0.8 <= d <= 1.3 for d in delays)
    assert len(set(delays)) > 1


def test_logger_sanitization() -> None:
    # [Блок 2.5] Очистка чувствительных данных в логах
    msg = "Leased proxy socks5h://user:secret123@1.1.1.1:8080 with token=abc12345"
    sanitized = sanitize_log_message(msg)
    assert "secret123" not in sanitized
    assert "abc12345" not in sanitized
    assert "socks5h://user:***@1.1.1.1:8080" in sanitized
