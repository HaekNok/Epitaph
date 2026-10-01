"""Комплексный набор тестов для модуля eMail-разведки (Слот 3), реестра и 52 чекеров."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock
import httpx
import pytest

from epitaph.execution.checkers.email.base import BaseEmailChecker
from epitaph.execution.checkers.email.executor import (
    AdobeEmailChecker,
    AirbnbEmailChecker,
    AmazonEmailChecker,
    AppleEmailChecker,
    AtlassianEmailChecker,
    BitwardenEmailChecker,
    BookingEmailChecker,
    ChessEmailChecker,
    CodecademyEmailChecker,
    DeezerEmailChecker,
    DiscordEmailChecker,
    DockerEmailChecker,
    DuolingoEmailChecker,
    EBayEmailChecker,
    EmailReconExecutor,
    EpicGamesEmailChecker,
    EvernoteEmailChecker,
    FacebookEmailChecker,
    FlickrEmailChecker,
    FreelancerEmailChecker,
    GitHubEmailChecker,
    GitLabEmailChecker,
    GravatarEmailChecker,
    HeadhunterEmailChecker,
    InstagramEmailChecker,
    LastPassEmailChecker,
    LinkedInEmailChecker,
    MediumEmailChecker,
    MegaEmailChecker,
    MicrosoftEmailChecker,
    MyFitnessPalEmailChecker,
    NetflixEmailChecker,
    NotionEmailChecker,
    OlxEmailChecker,
    PatreonEmailChecker,
    PayPalEmailChecker,
    PinterestEmailChecker,
    ProtonMailEmailChecker,
    QuoraEmailChecker,
    RedditEmailChecker,
    RobotaUaEmailChecker,
    SlackEmailChecker,
    SnapchatEmailChecker,
    SpotifyEmailChecker,
    SteamEmailChecker,
    StravaEmailChecker,
    TikTokEmailChecker,
    TripAdvisorEmailChecker,
    TumblrEmailChecker,
    TwitchEmailChecker,
    TwitterEmailChecker,
    WordPressEmailChecker,
    WorkUaEmailChecker,
)
from epitaph.execution.checkers.email.registry import EmailCheckerRegistry
from epitaph.models.base import DetectionStatus
from epitaph.models.result import CheckResult
from epitaph.models.target import TargetProfile


def test_email_checker_registry_discovery() -> None:
    # Проверка обнаружения и регистрации всех 52 специализированных чекеров из единого модуля
    checkers = EmailCheckerRegistry.get_all_instances()
    names = {c.name.lower() for c in checkers}
    expected = {
        # Исходные 22 сервиса
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
        # 30 новых сервисов
        "adobe",
        "amazon",
        "airbnb",
        "bitwarden",
        "booking.com",
        "chess.com",
        "codecademy",
        "deezer",
        "ebay",
        "epic games",
        "evernote",
        "facebook",
        "flickr",
        "freelancer",
        "lastpass",
        "linkedin",
        "medium",
        "myfitnesspal",
        "netflix",
        "notion",
        "patreon",
        "paypal",
        "quora",
        "reddit",
        "slack",
        "strava",
        "tripadvisor",
        "tumblr",
        "twitch",
        "wordpress",
    }
    assert expected.issubset(names)
    assert len(checkers) >= 52


def test_opsec_active_probe_marking() -> None:
    # Проверка корректности маркировки активных чекеров с риском уведомления цели
    active_names = {"discord", "github", "work.ua", "gitlab", "olx", "linkedin"}
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
    assert "linkedin" not in ran_platforms


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
async def test_adobe_checker_success() -> None:
    # Проверка обнаружения аккаунта в Adobe
    checker = AdobeEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = [{"accountType": "type1", "userId": "12345"}]
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="designer@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Adobe"


@pytest.mark.asyncio
async def test_chess_checker_success() -> None:
    # Проверка обнаружения аккаунта на Chess.com
    checker = ChessEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"available": False}
    mock_client.get.return_value = mock_resp

    target = TargetProfile(username="grandmaster@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Chess.com"


@pytest.mark.asyncio
async def test_notion_checker_success() -> None:
    # Проверка обнаружения аккаунта в Notion
    checker = NotionEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"hasPassword": True, "hasGoogleLogin": False}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="workspace@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Notion"
