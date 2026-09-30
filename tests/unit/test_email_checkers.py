"""Модульные тесты для подсистемы проверки email-адресов (Holehe Core)."""
from __future__ import annotations

import hashlib
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from epitaph.execution.checkers.email.base import BaseEmailChecker
from epitaph.execution.checkers.email.registry import EmailCheckerRegistry
from epitaph.execution.checkers.email.services.discord import DiscordEmailChecker
from epitaph.execution.checkers.email.services.github import GitHubEmailChecker
from epitaph.execution.checkers.email.services.gravatar import GravatarEmailChecker
from epitaph.execution.checkers.email.services.instagram import InstagramEmailChecker
from epitaph.execution.checkers.email.services.spotify import SpotifyEmailChecker
from epitaph.execution.checkers.email.services.twitter import TwitterEmailChecker
from epitaph.models.base import DetectionStatus
from epitaph.models.target import TargetProfile


class DummyEmailChecker(BaseEmailChecker):
    @property
    def name(self) -> str:
        return "Dummy"

    async def probe_email(self, email: str, target: TargetProfile, client, start_time: float):
        return self.create_result(target=target, status=DetectionStatus.FOUND, response_time_ms=10.0)


def test_sanitize_email():
    checker = DummyEmailChecker()
    # Валидные адреса нормализуются к нижнему регистру
    assert checker.sanitize_email("User.Name@Example.COM") == "user.name@example.com"
    assert checker.sanitize_email("test+tag@domain.org") == "test+tag@domain.org"

    # Невалидные адреса вызывают ValueError
    with pytest.raises(ValueError):
        checker.sanitize_email("invalid-email")
    with pytest.raises(ValueError):
        checker.sanitize_email("@nodomain.com")
    with pytest.raises(ValueError):
        checker.sanitize_email("user@")


def test_extract_csrf():
    checker = DummyEmailChecker()
    html = '<form><input type="hidden" name="authenticity_token" value="test_token_123" /></form>'
    token = checker.extract_csrf(html, r'name="authenticity_token"\s+value="([^"]+)"')
    assert token == "test_token_123"

    assert checker.extract_csrf(html, r'name="nonexistent"\s+value="([^"]+)"') is None


def test_registry_registration():
    all_instances = EmailCheckerRegistry.get_all_instances()
    names = {c.name.lower() for c in all_instances}
    expected = {"github", "twitter", "instagram", "discord", "spotify", "gravatar"}
    assert expected.issubset(names)


@pytest.mark.asyncio
async def test_github_checker_flow():
    checker = GitHubEmailChecker()
    target = TargetProfile(username="target@example.com")
    client = AsyncMock()

    # Сценарий NOT_FOUND
    client.get.return_value = MagicMock(
        status_code=200,
        text='<input name="authenticity_token" value="token_val" />'
    )
    client.post.return_value = MagicMock(status_code=200, text="Can't find that email")
    res = await checker.probe_email("target@example.com", target, client, time.monotonic())
    assert res.status == DetectionStatus.NOT_FOUND

    # Сценарий FOUND
    client.post.return_value = MagicMock(status_code=302, text="")
    res_found = await checker.probe_email("target@example.com", target, client, time.monotonic())
    assert res_found.status == DetectionStatus.FOUND
    assert res_found.profile_url == "https://github.com"


@pytest.mark.asyncio
async def test_twitter_checker_flow():
    checker = TwitterEmailChecker()
    target = TargetProfile(username="target@example.com")
    client = AsyncMock()

    # Сценарий FOUND
    client.get.return_value = MagicMock(status_code=200, json=lambda: {"taken": True})
    res_found = await checker.probe_email("target@example.com", target, client, time.monotonic())
    assert res_found.status == DetectionStatus.FOUND
    assert res_found.profile_url == "https://x.com"

    # Сценарий NOT_FOUND
    client.get.return_value = MagicMock(status_code=200, json=lambda: {"taken": False})
    res_not_found = await checker.probe_email("target@example.com", target, client, time.monotonic())
    assert res_not_found.status == DetectionStatus.NOT_FOUND


@pytest.mark.asyncio
async def test_spotify_checker_flow():
    checker = SpotifyEmailChecker()
    target = TargetProfile(username="target@example.com")
    client = AsyncMock()

    # status 20 -> FOUND
    client.get.return_value = MagicMock(status_code=200, json=lambda: {"status": 20})
    res_found = await checker.probe_email("target@example.com", target, client, time.monotonic())
    assert res_found.status == DetectionStatus.FOUND

    # status 1 -> NOT_FOUND
    client.get.return_value = MagicMock(status_code=200, json=lambda: {"status": 1})
    res_not_found = await checker.probe_email("target@example.com", target, client, time.monotonic())
    assert res_not_found.status == DetectionStatus.NOT_FOUND


@pytest.mark.asyncio
async def test_gravatar_checker_flow():
    checker = GravatarEmailChecker()
    email = "test@example.com"
    email_hash = hashlib.md5(email.encode("utf-8")).hexdigest()
    target = TargetProfile(username=email)
    client = AsyncMock()

    client.get.return_value = MagicMock(
        status_code=200,
        json=lambda: {"entry": [{"displayName": "Test User", "currentLocation": "Kyiv"}]}
    )
    res_found = await checker.probe_email(email, target, client, time.monotonic())
    assert res_found.status == DetectionStatus.FOUND
    assert res_found.extracted_data.get("display_name") == "Test User"
    assert res_found.profile_url == f"https://gravatar.com/{email_hash}"

    client.get.return_value = MagicMock(status_code=404)
    res_not_found = await checker.probe_email(email, target, client, time.monotonic())
    assert res_not_found.status == DetectionStatus.NOT_FOUND
