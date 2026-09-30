"""Комплексный набор тестов для модуля eMail-разведки (Слот 2), реестра и чекеров."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock
import httpx
import pytest

from epitaph.execution.checkers.email.base import BaseEmailChecker
from epitaph.execution.checkers.email.executor import EmailReconExecutor
from epitaph.execution.checkers.email.registry import EmailCheckerRegistry
from epitaph.execution.checkers.email.services.github import GitHubEmailChecker
from epitaph.execution.checkers.email.services.gravatar import GravatarEmailChecker
from epitaph.execution.checkers.email.services.spotify import SpotifyEmailChecker
from epitaph.execution.checkers.email.services.twitter import TwitterEmailChecker
from epitaph.models.base import DetectionStatus
from epitaph.models.result import CheckResult
from epitaph.models.target import TargetProfile


def test_email_checker_registry_discovery() -> None:
    # Проверка обнаружения и регистрации всех 12 специализированных чекеров
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
    }
    assert expected.issubset(names)
    assert len(checkers) >= 12


def test_opsec_active_probe_marking() -> None:
    # Проверка корректности маркировки активных чекеров с риском уведомления цели
    active_names = {"discord", "github", "work.ua"}
    for checker in EmailCheckerRegistry.get_all_instances():
        if checker.name.lower() in active_names:
            assert checker.is_active_probe is True, f"Чекер {checker.name} должен быть active_probe"
        else:
            assert checker.is_active_probe is False, f"Чекер {checker.name} должен быть пассивным"


def test_base_email_sanitization() -> None:
    # Проверка очистки пробелов, приведения к нижнему регистру и отсечения CRLF
    checker = GravatarEmailChecker()
    clean = checker.sanitize_email("  Test.User+Filter@Example.COM \r\n")
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
    target = TargetProfile(username="  super_target  ")
    session_res = await executor.run_search(target)

    assert session_res.target.username == "super_target@gmail.com"


@pytest.mark.asyncio
async def test_email_recon_executor_taskgroup_resilience() -> None:
    # Проверка устойчивости TaskGroup: сбой в одном чекере не останавливает остальные
    queue: asyncio.Queue[object] = asyncio.Queue()
    mock_engine = MagicMock()

    async def side_effect(checker, target):
        if getattr(checker, "name", "") == "Spotify":
            raise RuntimeError("Искусственный сбой соединения")
        return CheckResult(
            platform_name=checker.name,
            target=target,
            status=DetectionStatus.FOUND,
        )

    mock_engine.scheduler.run_checker = AsyncMock(side_effect=side_effect)
    mock_engine.dispatcher.export_all = AsyncMock(return_value=[])

    executor = EmailReconExecutor(event_queue=queue, engine=mock_engine, passive_mode=True)
    target = TargetProfile(username="user@example.com")
    session_res = await executor.run_search(target)

    spotify_res = next((r for r in session_res.results if r.platform_name == "Spotify"), None)
    assert spotify_res is not None
    assert spotify_res.status == DetectionStatus.ERROR
    assert "Искусственный сбой" in (spotify_res.error_message or "")
    assert session_res.found_count > 0


@pytest.mark.asyncio
async def test_gravatar_email_checker_success() -> None:
    # Проверка работы чекера Gravatar с MD5-хэшированием и парсингом профиля
    checker = GravatarEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "entry": [{"displayName": "Test Analyst", "currentLocation": "Kyiv, Ukraine"}]
    }
    mock_client.get.return_value = mock_resp

    target = TargetProfile(username="user@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Gravatar"
    assert result.extracted_data.get("display_name") == "Test Analyst"
    assert result.extracted_data.get("location") == "Kyiv, Ukraine"


@pytest.mark.asyncio
async def test_spotify_param_encoding() -> None:
    # Проверка передачи email в параметрах запроса Spotify для защиты спецсимволов
    checker = SpotifyEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": 20}
    mock_client.get.return_value = mock_resp

    target = TargetProfile(username="user+tag@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    call_kwargs = mock_client.get.call_args.kwargs
    assert call_kwargs.get("params") == {"validate": "1", "email": "user+tag@example.com"}
