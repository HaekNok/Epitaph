"""Комплексный набор тестов для модуля eMail-разведки (Слот 3), реестра и чекеров."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock
import httpx
import pytest

from epitaph.execution.checkers.email.base import BaseEmailChecker
from epitaph.execution.checkers.email.executor import (
    EmailReconExecutor,
    GitHubEmailChecker,
    GravatarEmailChecker,
    SpotifyEmailChecker,
    TwitterEmailChecker,
    MicrosoftEmailChecker,
    DuolingoEmailChecker,
    ProtonMailEmailChecker,
    MegaEmailChecker,
)
from epitaph.execution.checkers.email.registry import EmailCheckerRegistry
from epitaph.models.base import DetectionStatus
from epitaph.models.result import CheckResult
from epitaph.models.target import TargetProfile


def test_email_checker_registry_discovery() -> None:
    # Проверка обнаружения и регистрации всех 22 специализированных чекеров из единого модуля
    checkers = EmailCheckerRegistry.get_all_instances()
    names = {c.name.lower() for c in checkers}
    expected = {
        "discord",
        "github",
        "gravatar",
        "headhunter",
        "instagram",
        "robota.ua",
        "snapchat",
        "spotify",
        "steam",
        "tiktok",
        "twitter",
        "work.ua",
        "microsoft",
        "duolingo",
        "gitlab",
        "mega",
        "protonmail",
        "apple id",
        "atlassian",
        "pinterest",
        "olx",
        "docker hub",
    }
    assert expected.issubset(names)
    assert len(checkers) >= 22


def test_opsec_active_probe_marking() -> None:
    # Проверка корректности маркировки активных чекеров с риском уведомления цели
    active_names = {"discord", "github", "work.ua", "gitlab", "olx"}
    for checker in EmailCheckerRegistry.get_all_instances():
        if checker.name.lower() in active_names:
            assert checker.is_active_probe is True, f"Чекер {checker.name} должен быть active_probe"
        else:
            assert checker.is_active_probe is False, f"Чекер {checker.name} должен быть пассивным"


def test_base_email_sanitization() -> None:
    # Проверка очистки пробелов, приведения к нижнему регистру и отсечения CRLF
    checker = GravatarEmailChecker()
    clean = checker.sanitize_email(" Test.User+Filter@Example.COM \r\n")
    assert clean == "test.user+filter@example.com"

    with pytest.raises(ValueError, match="Некорректный формат email"):
        checker.sanitize_email("invalid_email_string")

    with pytest.raises(ValueError, match="Некорректный формат email"):
        checker.sanitize_email("user@domain\r\nbcc:evil@attacker.com")


@pytest.mark.asyncio
async def test_email_recon_executor_passive_mode_filtering() -> None:
    # Проверка пропуска активных чекеров при включенном пассивном режиме
    queue: asyncio.Queue[object] = asyncio.Queue()
    mock_engine = MagicMock()
    mock_engine.scheduler.run_checker = AsyncMock(
        return_value=CheckResult(
            platform_name="Mock",
            target=TargetProfile(username="analyst@gmail.com"),
            status=DetectionStatus.FOUND,
        )
    )
    mock_engine.dispatcher.export_all = AsyncMock(return_value=[])

    executor = EmailReconExecutor(event_queue=queue, engine=mock_engine, passive_mode=True)
    target = TargetProfile(username="analyst@gmail.com")
    session_res = await executor.run_search(target)

    ran_platforms = {r.platform_name.lower() for r in session_res.results}
    assert "github" not in ran_platforms
    assert "discord" not in ran_platforms
    assert "work.ua" not in ran_platforms
    assert "gitlab" not in ran_platforms
    assert "olx" not in ran_platforms
    assert "google" in ran_platforms


@pytest.mark.asyncio
async def test_email_recon_executor_input_normalization() -> None:
    # Проверка автоматической нормализации никнейма без @ к формату gmail
    queue: asyncio.Queue[object] = asyncio.Queue()
    mock_engine = MagicMock()
    mock_engine.scheduler.run_checker = AsyncMock(
        return_value=CheckResult(
            platform_name="Mock",
            target=TargetProfile(username="target@gmail.com"),
            status=DetectionStatus.FOUND,
        )
    )
    mock_engine.dispatcher.export_all = AsyncMock(return_value=[])

    executor = EmailReconExecutor(event_queue=queue, engine=mock_engine)
    target = TargetProfile(username=" super_target ")
    session_res = await executor.run_search(target)

    assert session_res.target.username == "super_target@gmail.com"


@pytest.mark.asyncio
async def test_microsoft_checker_success() -> None:
    checker = MicrosoftEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"IfExistsResult": 0, "UserTenantType": "Personal"}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="user@live.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Microsoft"
    assert result.profile_url == "https://account.microsoft.com"
    assert result.extracted_data.get("tenant_type") == "Personal"


@pytest.mark.asyncio
async def test_duolingo_checker_success() -> None:
    checker = DuolingoEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "users": [{
            "username": "polyglot_user",
            "name": "Polyglot",
            "learningLanguage": "es",
            "picture": "//avatar.duolingo.com/pic.jpg",
        }]
    }
    mock_client.get.return_value = mock_resp

    target = TargetProfile(username="user@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Duolingo"
    assert result.profile_url == "https://www.duolingo.com/profile/polyglot_user"
    assert result.extracted_data.get("username") == "polyglot_user"
    assert result.extracted_data.get("learning_language") == "es"


@pytest.mark.asyncio
async def test_protonmail_checker_success() -> None:
    checker = ProtonMailEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.text = "info:1:1\npub:4096R/1234ABCD"
    mock_client.get.return_value = mock_resp

    target = TargetProfile(username="analyst@proton.me")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "ProtonMail"
    assert result.profile_url == "https://proton.me"


@pytest.mark.asyncio
async def test_mega_checker_success() -> None:
    checker = MegaEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = [{"v": 1, "k": "sample_encryption_key"}]
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="user@mega.nz")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Mega"
    assert result.profile_url == "https://mega.nz"
