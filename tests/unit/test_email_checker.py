"""Комплексный набор тестов для модуля eMail-разведки (Слот 3), реестра и 97 чекеров."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock
import httpx
import pytest

from epitaph.execution.checkers.email.base import BaseEmailChecker
from epitaph.execution.checkers.email.executor import (
    DropboxEmailChecker,
    ShopifyEmailChecker,
    AsanaEmailChecker,
    CanvaEmailChecker,
    VimeoEmailChecker,
    CoinbaseEmailChecker,
    FigmaEmailChecker,
    TradingViewEmailChecker,
    ZoomEmailChecker,
    DeliverooEmailChecker,
    GrammarlyEmailChecker,
    ReplitEmailChecker,
    BandcampEmailChecker,
    KickEmailChecker,
    VercelEmailChecker,
    MailchimpEmailChecker,
    PostmanEmailChecker,
    StripeEmailChecker,
    GitKrakenEmailChecker,
    HubSpotEmailChecker,
    KaggleEmailChecker,
    BitlyEmailChecker,
    CourseraEmailChecker,
    WiseEmailChecker,
    HerokuEmailChecker,
    LetterboxdEmailChecker,
    SubstackEmailChecker,
    DribbbleEmailChecker,
    KrakenEmailChecker,
    TwilioEmailChecker,
    OnePasswordEmailChecker,
    PastebinEmailChecker,
    ProductHuntEmailChecker,
    BybitEmailChecker,
    IftttEmailChecker,
    SkillshareEmailChecker,
    BitdefenderEmailChecker,
    DeviantArtEmailChecker,
    GoodreadsEmailChecker,
    AdobeEmailChecker,
    BinanceEmailChecker,
    BitbucketEmailChecker,
    ImgurEmailChecker,
    SoundCloudEmailChecker,
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
    SamsungEmailChecker,
    YahooEmailChecker,
    WorkUaEmailChecker,
    UdemyEmailChecker,
    MiroEmailChecker,
    AirtableEmailChecker,
    DigitalOceanEmailChecker,
    ClickUpEmailChecker,
    LeetCodeEmailChecker,
    WebflowEmailChecker,
    GogEmailChecker,
    LoomEmailChecker,
    FiverrEmailChecker,
    KickstarterEmailChecker,
    MondayEmailChecker,
    ZendeskEmailChecker,
    KhanAcademyEmailChecker,
    LichessEmailChecker,
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
        "bitbucket",
        "soundcloud",
        "imgur",
        "yahoo",
        "samsung",
        "binance",
        "dropbox",
        "shopify",
        "asana",
        "canva",
        "vimeo",
        "coinbase",
        "tradingview",
        "zoom",
        "figma",
        "grammarly",
        "deliveroo",
        "replit",
        "kick",
        "vercel",
        "bandcamp",
        "postman",
        "mailchimp",
        "stripe",
        "hubspot",
        "kaggle",
        "gitkraken",
        "wise",
        "bitly",
        "coursera",
        "substack",
        "letterboxd",
        "heroku",
        "twilio",
        "kraken",
        "dribbble",
        "onepassword",
        "producthunt",
        "pastebin",
        "skillshare",
        "ifttt",
        "bybit",
        "bitdefender",
        "deviantart",
        "goodreads",
    }
    assert expected.issubset(names)
    assert len(checkers) >= 97


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

@pytest.mark.asyncio
async def test_bitbucket_checker_success() -> None:
    # Проверка обнаружения аккаунта в Bitbucket
    checker = BitbucketEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"accountExists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="developer@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Bitbucket"


@pytest.mark.asyncio
async def test_soundcloud_checker_success() -> None:
    # Проверка обнаружения профиля в SoundCloud
    checker = SoundCloudEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "existing_user", "auth_method": "password"}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="musician@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "SoundCloud"

@pytest.mark.asyncio
async def test_binance_checker_success() -> None:
    # Проверка обнаружения аккаунта на бирже Binance
    checker = BinanceEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"success": True, "data": {"userExists": True}}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="trader@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Binance"


@pytest.mark.asyncio
async def test_samsung_checker_success() -> None:
    # Проверка обнаружения аккаунта в Samsung
    checker = SamsungEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"isAvailable": False}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="galaxy@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Samsung"

@pytest.mark.asyncio
async def test_dropbox_checker_success() -> None:
    # Проверка обнаружения аккаунта в Dropbox
    checker = DropboxEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "OK", "exists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="user@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Dropbox"


@pytest.mark.asyncio
async def test_shopify_checker_success() -> None:
    # Проверка обнаружения аккаунта в Shopify
    checker = ShopifyEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"lookup_result": "account_exists", "account_exists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="merchant@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Shopify"


@pytest.mark.asyncio
async def test_asana_checker_success() -> None:
    # Проверка обнаружения корпоративного аккаунта в Asana
    checker = AsanaEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"data": {"user_exists": True}}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="manager@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Asana"

@pytest.mark.asyncio
async def test_canva_checker_success() -> None:
    # Проверка обнаружения аккаунта в Canva
    checker = CanvaEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"user_exists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="designer@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Canva"


@pytest.mark.asyncio
async def test_vimeo_checker_success() -> None:
    # Проверка обнаружения аккаунта в Vimeo
    checker = VimeoEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "fail", "message": "Email address already in use."}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="creator@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Vimeo"


@pytest.mark.asyncio
async def test_coinbase_checker_success() -> None:
    # Проверка обнаружения аккаунта в Coinbase
    checker = CoinbaseEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"data": {"exists": True}}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="investor@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Coinbase"

@pytest.mark.asyncio
async def test_tradingview_checker_success() -> None:
    # Проверка обнаружения аккаунта в TradingView
    checker = TradingViewEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"email_exists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="trader@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "TradingView"


@pytest.mark.asyncio
async def test_zoom_checker_success() -> None:
    # Проверка обнаружения аккаунта в Zoom
    checker = ZoomEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"result": "EXISTED", "existed": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="meeting@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Zoom"


@pytest.mark.asyncio
async def test_figma_checker_success() -> None:
    # Проверка обнаружения аккаунта в Figma
    checker = FigmaEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"exists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="designer@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Figma"

@pytest.mark.asyncio
async def test_grammarly_checker_success() -> None:
    # Проверка обнаружения аккаунта в Grammarly
    checker = GrammarlyEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"isNewUser": False}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="writer@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Grammarly"


@pytest.mark.asyncio
async def test_deliveroo_checker_success() -> None:
    # Проверка обнаружения аккаунта в Deliveroo
    checker = DeliverooEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"registered": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="customer@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Deliveroo"


@pytest.mark.asyncio
async def test_replit_checker_success() -> None:
    # Проверка обнаружения аккаунта в Replit
    checker = ReplitEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"exists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="coder@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Replit"

@pytest.mark.asyncio
async def test_kick_checker_success() -> None:
    # Проверка обнаружения аккаунта в Kick
    checker = KickEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"is_available": False, "taken": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="streamer@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Kick"


@pytest.mark.asyncio
async def test_vercel_checker_success() -> None:
    # Проверка обнаружения аккаунта в Vercel
    checker = VercelEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"exists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="frontend@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Vercel"


@pytest.mark.asyncio
async def test_bandcamp_checker_success() -> None:
    # Проверка обнаружения аккаунта в Bandcamp
    checker = BandcampEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"error": "email_taken"}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="musician@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Bandcamp"

@pytest.mark.asyncio
async def test_postman_checker_success() -> None:
    # Проверка обнаружения аккаунта в Postman
    checker = PostmanEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"user_exists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="developer@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Postman"


@pytest.mark.asyncio
async def test_mailchimp_checker_success() -> None:
    # Проверка обнаружения аккаунта в Mailchimp
    checker = MailchimpEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"taken": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="marketing@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Mailchimp"


@pytest.mark.asyncio
async def test_stripe_checker_success() -> None:
    # Проверка обнаружения аккаунта в Stripe
    checker = StripeEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"has_account": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="business@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Stripe"

@pytest.mark.asyncio
async def test_hubspot_checker_success() -> None:
    # Проверка обнаружения аккаунта в HubSpot
    checker = HubSpotEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"userExists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="crm@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "HubSpot"


@pytest.mark.asyncio
async def test_kaggle_checker_success() -> None:
    # Проверка обнаружения аккаунта в Kaggle
    checker = KaggleEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"is_available": False, "exists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="datascientist@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Kaggle"


@pytest.mark.asyncio
async def test_gitkraken_checker_success() -> None:
    # Проверка обнаружения аккаунта в GitKraken
    checker = GitKrakenEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"exists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="gitdev@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "GitKraken"

@pytest.mark.asyncio
async def test_wise_checker_success() -> None:
    # Проверка обнаружения аккаунта в Wise
    checker = WiseEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"exists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="finance@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Wise"


@pytest.mark.asyncio
async def test_bitly_checker_success() -> None:
    # Проверка обнаружения аккаунта в Bitly
    checker = BitlyEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"exists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="marketer@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Bitly"


@pytest.mark.asyncio
async def test_coursera_checker_success() -> None:
    # Проверка обнаружения аккаунта в Coursera
    checker = CourseraEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"elements": [{"exists": True}]}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="student@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Coursera"

@pytest.mark.asyncio
async def test_substack_checker_success() -> None:
    # Проверка обнаружения аккаунта в Substack
    checker = SubstackEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"exists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="writer@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Substack"


@pytest.mark.asyncio
async def test_letterboxd_checker_success() -> None:
    # Проверка обнаружения аккаунта в Letterboxd
    checker = LetterboxdEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"result": "taken"}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="cinephile@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Letterboxd"


@pytest.mark.asyncio
async def test_heroku_checker_success() -> None:
    # Проверка обнаружения аккаунта в Heroku
    checker = HerokuEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"taken": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="developer@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Heroku"

@pytest.mark.asyncio
async def test_twilio_checker_success() -> None:
    # Проверка обнаружения аккаунта в Twilio
    checker = TwilioEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"exists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="comms@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Twilio"


@pytest.mark.asyncio
async def test_kraken_checker_success() -> None:
    # Проверка обнаружения аккаунта в Kraken
    checker = KrakenEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"result": {"exists": True}}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="trader@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Kraken"


@pytest.mark.asyncio
async def test_dribbble_checker_success() -> None:
    # Проверка обнаружения аккаунта в Dribbble
    checker = DribbbleEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"taken": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="artist@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Dribbble"

@pytest.mark.asyncio
async def test_onepassword_checker_success() -> None:
    # Проверка обнаружения аккаунта в 1Password
    checker = OnePasswordEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"account_exists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="security@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "1Password"


@pytest.mark.asyncio
async def test_producthunt_checker_success() -> None:
    # Проверка обнаружения аккаунта в Product Hunt
    checker = ProductHuntEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"exists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="founder@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Product Hunt"


@pytest.mark.asyncio
async def test_pastebin_checker_success() -> None:
    # Проверка обнаружения аккаунта в Pastebin
    checker = PastebinEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "taken"}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="coder@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Pastebin"

@pytest.mark.asyncio
async def test_skillshare_checker_success() -> None:
    # Проверка обнаружения аккаунта в Skillshare
    checker = SkillshareEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"exists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="student@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Skillshare"


@pytest.mark.asyncio
async def test_ifttt_checker_success() -> None:
    # Проверка обнаружения аккаунта в IFTTT
    checker = IftttEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"exists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="automation@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "IFTTT"


@pytest.mark.asyncio
async def test_bybit_checker_success() -> None:
    # Проверка обнаружения аккаунта в Bybit
    checker = BybitEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"result": {"hasRegistered": True}}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="trader@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Bybit"

@pytest.mark.asyncio
async def test_bitdefender_checker_success() -> None:
    # Проверка обнаружения аккаунта в Bitdefender
    checker = BitdefenderEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"exists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="security@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Bitdefender"


@pytest.mark.asyncio
async def test_deviantart_checker_success() -> None:
    # Проверка обнаружения аккаунта в DeviantArt
    checker = DeviantArtEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"is_available": False, "taken": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="artist@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "DeviantArt"


@pytest.mark.asyncio
async def test_goodreads_checker_success() -> None:
    # Проверка обнаружения аккаунта в Goodreads
    checker = GoodreadsEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"taken": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="reader@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Goodreads"

@pytest.mark.asyncio
async def test_udemy_checker_success() -> None:
    # Проверка обнаружения аккаунта в Udemy
    checker = UdemyEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"is_available": False, "taken": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="student@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Udemy"


@pytest.mark.asyncio
async def test_miro_checker_success() -> None:
    # Проверка обнаружения аккаунта в Miro
    checker = MiroEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"exists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="designer@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Miro"


@pytest.mark.asyncio
async def test_airtable_checker_success() -> None:
    # Проверка обнаружения аккаунта в Airtable
    checker = AirtableEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"doesUserExist": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="developer@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Airtable"

@pytest.mark.asyncio
async def test_digitalocean_checker_success() -> None:
    # Проверка обнаружения аккаунта в DigitalOcean
    checker = DigitalOceanEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"is_available": False, "taken": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="devops@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "DigitalOcean"


@pytest.mark.asyncio
async def test_clickup_checker_success() -> None:
    # Проверка обнаружения аккаунта в ClickUp
    checker = ClickUpEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"exists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="manager@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "ClickUp"


@pytest.mark.asyncio
async def test_leetcode_checker_success() -> None:
    # Проверка обнаружения аккаунта в LeetCode
    checker = LeetCodeEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"taken": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="coder@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "LeetCode"

@pytest.mark.asyncio
async def test_webflow_checker_success() -> None:
    # Проверка обнаружения аккаунта в Webflow
    checker = WebflowEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"isAvailable": False, "taken": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="designer@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Webflow"


@pytest.mark.asyncio
async def test_gog_checker_success() -> None:
    # Проверка обнаружения аккаунта в GOG
    checker = GogEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"taken": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="gamer@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "GOG"


@pytest.mark.asyncio
async def test_loom_checker_success() -> None:
    # Проверка обнаружения аккаунта в Loom
    checker = LoomEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"hasAccount": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="video@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Loom"

@pytest.mark.asyncio
async def test_fiverr_checker_success() -> None:
    # Проверка обнаружения аккаунта в Fiverr
    checker = FiverrEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"taken": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="freelancer@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Fiverr"


@pytest.mark.asyncio
async def test_kickstarter_checker_success() -> None:
    # Проверка обнаружения аккаунта в Kickstarter
    checker = KickstarterEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"taken": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="creator@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Kickstarter"


@pytest.mark.asyncio
async def test_monday_checker_success() -> None:
    # Проверка обнаружения аккаунта в Monday.com
    checker = MondayEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"exists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="lead@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Monday.com"

@pytest.mark.asyncio
async def test_zendesk_checker_success() -> None:
    # Проверка обнаружения аккаунта в Zendesk
    checker = ZendeskEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"exists": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="support@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Zendesk"


@pytest.mark.asyncio
async def test_khanacademy_checker_success() -> None:
    # Проверка обнаружения аккаунта в Khan Academy
    checker = KhanAcademyEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"is_available": False, "taken": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="student@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Khan Academy"


@pytest.mark.asyncio
async def test_lichess_checker_success() -> None:
    # Проверка обнаружения аккаунта в Lichess
    checker = LichessEmailChecker()
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"taken": True}
    mock_client.post.return_value = mock_resp

    target = TargetProfile(username="chessmaster@example.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Lichess"

