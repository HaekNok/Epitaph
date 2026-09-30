"""Координатор сканирования по email для Слота 3 (Google OSINT + Service Checkers) с защитой OPSEC Fail-Closed и Passive Mode."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import json
import logging
from pathlib import Path
import re
import time
from typing import TYPE_CHECKING, Any, Callable, Dict, Final, List, Optional, Pattern
from urllib.parse import quote, urlencode
import uuid

import httpx

from epitaph.core.events import (
    CheckResultEvent,
    LogEvent,
    ProgressUpdateEvent,
    ScanCompletedEvent,
    StartScanEvent,
)
from epitaph.execution.checkers.email.base import BaseEmailChecker
from epitaph.execution.checkers.email.registry import EmailCheckerRegistry
from epitaph.execution.checkers.google.checker import GoogleAccountChecker
from epitaph.models.base import DetectionStatus
from epitaph.models.result import CheckResult, ScanSessionResult
from epitaph.models.target import TargetProfile
from epitaph.reporting.dispatcher import ReportDispatcher, get_default_report_dir

if TYPE_CHECKING:
    from epitaph.core.engine import ScanEngine

logger = logging.getLogger("epitaph.execution.checkers.email.executor")


# ==============================================================================
# 22 Платформенных Сервис-Чекеров eMail (Объединенная Модульная База)
# ==============================================================================

@EmailCheckerRegistry.register("steam")
class SteamEmailChecker(BaseEmailChecker):
    """Проверка наличия учетной записи Steam по email."""
    @property
    def name(self) -> str:
        return "Steam"

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        check_url = "https://store.steampowered.com/join/checkemail/"
        headers = self.default_headers.copy()
        headers.update({
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Origin": "https://store.steampowered.com",
            "Referer": "https://store.steampowered.com/join/",
            "X-Requested-With": "XMLHttpRequest",
        })
        payload = {"email": email, "count": 1}
        resp = await client.post(check_url, content=urlencode(payload), headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code == 200:
            try:
                data = resp.json()
                is_available = data.get("bAvailable")
                if is_available is False or data.get("is_available") == 0:
                    return self.create_result(
                        target=target,
                        status=DetectionStatus.FOUND,
                        response_time_ms=elapsed_ms,
                        http_status_code=200,
                        profile_url="https://steamcommunity.com",
                    )
                if is_available is True or data.get("is_available") == 1:
                    return self.create_result(
                        target=target,
                        status=DetectionStatus.NOT_FOUND,
                        response_time_ms=elapsed_ms,
                        http_status_code=200,
                    )
            except Exception:
                pass

        if resp.status_code in (403, 429):
            return self.create_result(
                target=target,
                status=DetectionStatus.BLOCKED if resp.status_code == 403 else DetectionStatus.RATE_LIMITED,
                response_time_ms=elapsed_ms,
                http_status_code=resp.status_code,
            )

        return self.create_result(
            target=target,
            status=DetectionStatus.ERROR,
            response_time_ms=elapsed_ms,
            http_status_code=resp.status_code,
            error_message="Некорректный ответ Steam API",
        )


@EmailCheckerRegistry.register("github")
class GitHubEmailChecker(BaseEmailChecker):
    """Проверка наличия учетной записи GitHub по email через форму восстановления."""
    @property
    def name(self) -> str:
        return "GitHub"

    @property
    def is_active_probe(self) -> bool:
        return True

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        reset_page_url = "https://github.com/password_reset"
        headers = self.default_headers.copy()

        resp_get = await client.get(reset_page_url, headers=headers)
        if resp_get.status_code != 200:
            elapsed = (time.monotonic() - start_time) * 1000
            return self.create_result(
                target=target,
                status=DetectionStatus.ERROR,
                response_time_ms=elapsed,
                http_status_code=resp_get.status_code,
                error_message="Не удалось загрузить форму password_reset GitHub",
            )

        token = self.extract_csrf(
            resp_get.text,
            r'name="authenticity_token"\s+value="([^"]+)"',
        )
        if not token:
            elapsed = (time.monotonic() - start_time) * 1000
            return self.create_result(
                target=target,
                status=DetectionStatus.BLOCKED,
                response_time_ms=elapsed,
                error_message="CSRF токен GitHub не найден в разметке",
            )

        post_headers = headers.copy()
        post_headers.update({
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://github.com",
            "Referer": reset_page_url,
        })
        payload = {"authenticity_token": token, "email": email}
        resp_post = await client.post(reset_page_url, content=urlencode(payload), headers=post_headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if "Can't find that email" in resp_post.text or "not found" in resp_post.text:
            return self.create_result(
                target=target,
                status=DetectionStatus.NOT_FOUND,
                response_time_ms=elapsed_ms,
                http_status_code=resp_post.status_code,
            )

        if resp_post.status_code in (200, 302):
            return self.create_result(
                target=target,
                status=DetectionStatus.FOUND,
                response_time_ms=elapsed_ms,
                http_status_code=resp_post.status_code,
                profile_url="https://github.com",
            )

        return self.create_result(
            target=target,
            status=DetectionStatus.ERROR,
            response_time_ms=elapsed_ms,
            http_status_code=resp_post.status_code,
            error_message="Неоднозначный ответ сервиса сброса пароля GitHub",
        )


@EmailCheckerRegistry.register("twitter")
class TwitterEmailChecker(BaseEmailChecker):
    """Проверка доступности email в Twitter / X."""
    @property
    def name(self) -> str:
        return "Twitter"

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        api_url = f"https://api.twitter.com/i/users/email_available.json?email={quote(email)}"
        headers = self.default_headers.copy()
        headers.update({
            "Accept": "application/json",
            "Referer": "https://twitter.com/",
            "X-Twitter-Active-User": "yes",
        })
        resp = await client.get(api_url, headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code == 200:
            data = resp.json()
            is_taken = bool(data.get("taken", False))
            status = DetectionStatus.FOUND if is_taken else DetectionStatus.NOT_FOUND
            return self.create_result(
                target=target,
                status=status,
                response_time_ms=elapsed_ms,
                http_status_code=200,
                profile_url="https://x.com" if is_taken else None,
            )

        if resp.status_code in (403, 429):
            status = DetectionStatus.RATE_LIMITED if resp.status_code == 429 else DetectionStatus.BLOCKED
            return self.create_result(
                target=target,
                status=status,
                response_time_ms=elapsed_ms,
                http_status_code=resp.status_code,
                error_message="Twitter API отклонил запрос (WAF / Rate Limit)",
            )

        return self.create_result(
            target=target,
            status=DetectionStatus.ERROR,
            response_time_ms=elapsed_ms,
            http_status_code=resp.status_code,
            error_message="Некорректный код ответа от Twitter API",
        )


@EmailCheckerRegistry.register("instagram")
class InstagramEmailChecker(BaseEmailChecker):
    """Проверка регистрации email в Instagram."""
    @property
    def name(self) -> str:
        return "Instagram"

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        base_url = "https://www.instagram.com/accounts/emailsignup/"
        headers = self.default_headers.copy()

        resp_init = await client.get(base_url, headers=headers)
        csrf_token = resp_init.cookies.get("csrftoken")
        if not csrf_token:
            csrf_token = self.extract_csrf(resp_init.text, r'"csrf_token":"([^"]+)"')

        if not csrf_token:
            elapsed = (time.monotonic() - start_time) * 1000
            return self.create_result(
                target=target,
                status=DetectionStatus.BLOCKED,
                response_time_ms=elapsed,
                error_message="Instagram CSRF cookie не получен",
            )

        check_url = "https://www.instagram.com/api/v1/web/accounts/check_email/"
        post_headers = headers.copy()
        post_headers.update({
            "Content-Type": "application/x-www-form-urlencoded",
            "X-CSRFToken": csrf_token,
            "X-Requested-With": "XMLHttpRequest",
            "Referer": base_url,
            "Origin": "https://www.instagram.com",
        })
        resp = await client.post(check_url, data={"email": email}, headers=post_headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code == 200:
            data = resp.json()
            if data.get("email_is_taken") is True:
                return self.create_result(
                    target=target,
                    status=DetectionStatus.FOUND,
                    response_time_ms=elapsed_ms,
                    http_status_code=200,
                    profile_url="https://www.instagram.com",
                )
            if data.get("status") == "ok" and not data.get("email_is_taken"):
                return self.create_result(
                    target=target,
                    status=DetectionStatus.NOT_FOUND,
                    response_time_ms=elapsed_ms,
                    http_status_code=200,
                )

        if resp.status_code in (403, 429):
            return self.create_result(
                target=target,
                status=DetectionStatus.BLOCKED if resp.status_code == 403 else DetectionStatus.RATE_LIMITED,
                response_time_ms=elapsed_ms,
                http_status_code=resp.status_code,
            )

        return self.create_result(
            target=target,
            status=DetectionStatus.ERROR,
            response_time_ms=elapsed_ms,
            http_status_code=resp.status_code,
            error_message="Нестандартный ответ API Instagram",
        )


@EmailCheckerRegistry.register("discord")
class DiscordEmailChecker(BaseEmailChecker):
    """Проверка наличия учетной записи в Discord по email."""
    @property
    def name(self) -> str:
        return "Discord"

    @property
    def is_active_probe(self) -> bool:
        return True

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        api_url = "https://discord.com/api/v9/auth/forgot"
        headers = self.default_headers.copy()
        headers.update({
            "Content-Type": "application/json",
            "Origin": "https://discord.com",
            "Referer": "https://discord.com/login",
        })
        resp = await client.post(api_url, json={"login": email}, headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code == 204:
            return self.create_result(
                target=target,
                status=DetectionStatus.FOUND,
                response_time_ms=elapsed_ms,
                http_status_code=204,
                profile_url="https://discord.com",
            )

        if resp.status_code == 400:
            data = resp.json()
            if data.get("code") == 20014 or "not found" in str(data).lower():
                return self.create_result(
                    target=target,
                    status=DetectionStatus.NOT_FOUND,
                    response_time_ms=elapsed_ms,
                    http_status_code=400,
                )
            if "captcha_key" in data:
                return self.create_result(
                    target=target,
                    status=DetectionStatus.BLOCKED,
                    response_time_ms=elapsed_ms,
                    http_status_code=400,
                    error_message="Требуется решение hCaptcha",
                )

        if resp.status_code == 429:
            return self.create_result(
                target=target,
                status=DetectionStatus.RATE_LIMITED,
                response_time_ms=elapsed_ms,
                http_status_code=429,
                error_message="Discord Rate Limit",
            )

        return self.create_result(
            target=target,
            status=DetectionStatus.ERROR,
            response_time_ms=elapsed_ms,
            http_status_code=resp.status_code,
            error_message="Неизвестный ответ Discord API",
        )


@EmailCheckerRegistry.register("spotify")
class SpotifyEmailChecker(BaseEmailChecker):
    """Проверка наличия учетной записи Spotify по email."""
    @property
    def name(self) -> str:
        return "Spotify"

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        api_url = f"https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={quote(email)}"
        headers = self.default_headers.copy()
        headers.update({
            "App-Platform": "WebPlayer",
            "Origin": "https://www.spotify.com",
            "Referer": "https://www.spotify.com/",
        })
        resp = await client.get(api_url, headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code == 200:
            data = resp.json()
            code = data.get("status")
            if code == 20:
                return self.create_result(
                    target=target,
                    status=DetectionStatus.FOUND,
                    response_time_ms=elapsed_ms,
                    http_status_code=200,
                    profile_url="https://open.spotify.com",
                )
            if code == 1:
                return self.create_result(
                    target=target,
                    status=DetectionStatus.NOT_FOUND,
                    response_time_ms=elapsed_ms,
                    http_status_code=200,
                )

        if resp.status_code == 429:
            return self.create_result(
                target=target,
                status=DetectionStatus.RATE_LIMITED,
                response_time_ms=elapsed_ms,
                http_status_code=429,
            )

        return self.create_result(
            target=target,
            status=DetectionStatus.ERROR,
            response_time_ms=elapsed_ms,
            http_status_code=resp.status_code,
            error_message="Сбой проверки Spotify API",
        )


@EmailCheckerRegistry.register("gravatar")
class GravatarEmailChecker(BaseEmailChecker):
    """Проверка профиля Gravatar по email."""
    @property
    def name(self) -> str:
        return "Gravatar"

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        email_hash = hashlib.md5(email.encode("utf-8")).hexdigest()
        profile_url = f"https://en.gravatar.com/{email_hash}.json"
        avatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"

        headers = self.default_headers.copy()
        resp = await client.get(profile_url, headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code == 200:
            extracted: dict[str, object] = {"avatar_url": avatar_url}
            try:
                entry = resp.json().get("entry", [{}])[0]
                if "displayName" in entry:
                    extracted["display_name"] = entry["displayName"]
                if "currentLocation" in entry:
                    extracted["location"] = entry["currentLocation"]
            except Exception:
                pass

            return self.create_result(
                target=target,
                status=DetectionStatus.FOUND,
                response_time_ms=elapsed_ms,
                http_status_code=200,
                profile_url=f"https://gravatar.com/{email_hash}",
                extracted_data=extracted,
            )

        if resp.status_code == 404:
            return self.create_result(
                target=target,
                status=DetectionStatus.NOT_FOUND,
                response_time_ms=elapsed_ms,
                http_status_code=404,
            )

        return self.create_result(
            target=target,
            status=DetectionStatus.ERROR,
            response_time_ms=elapsed_ms,
            http_status_code=resp.status_code,
            error_message="Ошибка запроса к Gravatar",
        )


@EmailCheckerRegistry.register("tiktok")
class TikTokEmailChecker(BaseEmailChecker):
    """Проверка регистрации на платформе TikTok по email."""
    @property
    def name(self) -> str:
        return "TikTok"

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        params = {"aid": 1988, "email": email}
        api_url = f"https://passport.tiktok.com/passport/web/check_email_registered/?{urlencode(params)}"
        headers = self.default_headers.copy()
        headers.update({
            "Referer": "https://www.tiktok.com/signup",
            "Accept": "application/json",
        })
        resp = await client.get(api_url, headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code == 200:
            try:
                data = resp.json()
                data_obj = data.get("data", {})
                is_reg = data_obj.get("is_registered")
                if is_reg == 1:
                    return self.create_result(
                        target=target,
                        status=DetectionStatus.FOUND,
                        response_time_ms=elapsed_ms,
                        http_status_code=200,
                        profile_url="https://www.tiktok.com",
                    )
                if is_reg == 0:
                    return self.create_result(
                        target=target,
                        status=DetectionStatus.NOT_FOUND,
                        response_time_ms=elapsed_ms,
                        http_status_code=200,
                    )
            except Exception:
                pass

        if resp.status_code in (403, 429):
            return self.create_result(
                target=target,
                status=DetectionStatus.BLOCKED if resp.status_code == 403 else DetectionStatus.RATE_LIMITED,
                response_time_ms=elapsed_ms,
                http_status_code=resp.status_code,
            )

        return self.create_result(
            target=target,
            status=DetectionStatus.ERROR,
            response_time_ms=elapsed_ms,
            http_status_code=resp.status_code,
            error_message="Некорректный ответ TikTok API",
        )


@EmailCheckerRegistry.register("work.ua")
class WorkUaEmailChecker(BaseEmailChecker):
    """Проверка регистрации соискателя/работодателя на платформе Work.ua."""
    @property
    def name(self) -> str:
        return "Work.ua"

    @property
    def is_active_probe(self) -> bool:
        return True

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        pass_url = "https://www.work.ua/pass/"
        headers = self.default_headers.copy()
        headers.update({
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://www.work.ua",
            "Referer": pass_url,
        })
        payload = {"email": email}
        resp = await client.post(pass_url, content=urlencode(payload), headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        text = resp.text
        if "не знайдено" in text.lower() or "не найден" in text.lower():
            return self.create_result(
                target=target,
                status=DetectionStatus.NOT_FOUND,
                response_time_ms=elapsed_ms,
                http_status_code=resp.status_code,
            )

        if resp.status_code in (200, 302):
            if "надіслано" in text.lower() or "отправлено" in text.lower() or resp.status_code == 302:
                return self.create_result(
                    target=target,
                    status=DetectionStatus.FOUND,
                    response_time_ms=elapsed_ms,
                    http_status_code=resp.status_code,
                    profile_url="https://www.work.ua",
                )

        if resp.status_code in (403, 429):
            return self.create_result(
                target=target,
                status=DetectionStatus.BLOCKED if resp.status_code == 403 else DetectionStatus.RATE_LIMITED,
                response_time_ms=elapsed_ms,
                http_status_code=resp.status_code,
            )

        return self.create_result(
            target=target,
            status=DetectionStatus.ERROR,
            response_time_ms=elapsed_ms,
            http_status_code=resp.status_code,
            error_message="Неоднозначный ответ Work.ua",
        )


@EmailCheckerRegistry.register("robota.ua")
class RobotaUaEmailChecker(BaseEmailChecker):
    """Проверка наличия аккаунта на платформе Robota.ua."""
    @property
    def name(self) -> str:
        return "Robota.ua"

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        check_url = "https://api.robota.ua/auth/check-email"
        headers = self.default_headers.copy()
        headers.update({
            "Content-Type": "application/json; charset=UTF-8",
            "Origin": "https://robota.ua",
            "Referer": "https://robota.ua/auth/login",
            "Accept": "application/json",
        })
        payload = {"email": email}
        resp = await client.post(check_url, json=payload, headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code == 200:
            try:
                data = resp.json()
                exists = data.get("exists", data.get("isRegistered", False))
                status = DetectionStatus.FOUND if exists else DetectionStatus.NOT_FOUND
                return self.create_result(
                    target=target,
                    status=status,
                    response_time_ms=elapsed_ms,
                    http_status_code=200,
                    profile_url="https://robota.ua" if exists else None,
                )
            except Exception:
                pass

        if resp.status_code in (403, 429):
            return self.create_result(
                target=target,
                status=DetectionStatus.BLOCKED if resp.status_code == 403 else DetectionStatus.RATE_LIMITED,
                response_time_ms=elapsed_ms,
                http_status_code=resp.status_code,
            )

        return self.create_result(
            target=target,
            status=DetectionStatus.ERROR,
            response_time_ms=elapsed_ms,
            http_status_code=resp.status_code,
            error_message="Сбой проверки Robota.ua API",
        )


@EmailCheckerRegistry.register("headhunter")
class HeadhunterEmailChecker(BaseEmailChecker):
    """Проверка наличия аккаунта на платформе Headhunter (hh.ru)."""
    @property
    def name(self) -> str:
        return "Headhunter"

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        check_url = "https://hh.ru/account/check_login"
        headers = self.default_headers.copy()
        headers.update({
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": "https://hh.ru",
            "Referer": "https://hh.ru/account/login",
        })
        payload = {"login": email}
        resp = await client.post(check_url, content=urlencode(payload), headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code == 200:
            try:
                data = resp.json()
                is_valid = data.get("valid")
                exists = data.get("exists", not is_valid if is_valid is not None else False)
                status = DetectionStatus.FOUND if exists else DetectionStatus.NOT_FOUND
                return self.create_result(
                    target=target,
                    status=status,
                    response_time_ms=elapsed_ms,
                    http_status_code=200,
                    profile_url="https://hh.ru" if exists else None,
                )
            except Exception:
                pass

        if resp.status_code in (403, 429):
            return self.create_result(
                target=target,
                status=DetectionStatus.BLOCKED if resp.status_code == 403 else DetectionStatus.RATE_LIMITED,
                response_time_ms=elapsed_ms,
                http_status_code=resp.status_code,
            )

        return self.create_result(
            target=target,
            status=DetectionStatus.ERROR,
            response_time_ms=elapsed_ms,
            http_status_code=resp.status_code,
            error_message="Некорректный ответ Headhunter API",
        )


@EmailCheckerRegistry.register("snapchat")
class SnapchatEmailChecker(BaseEmailChecker):
    """Проверка регистрации через Bitmoji/Snapchat API."""
    @property
    def name(self) -> str:
        return "Snapchat"

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        api_url = "https://bitmoji.api.snapchat.com/api/user/find"
        headers = self.default_headers.copy()
        headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin": "https://accounts.snapchat.com",
        })
        payload = {"email": email}
        resp = await client.post(api_url, json=payload, headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code == 200:
            try:
                data = resp.json()
                if "user" in data or "avatar_url" in data or data.get("has_bitmoji") is True:
                    return self.create_result(
                        target=target,
                        status=DetectionStatus.FOUND,
                        response_time_ms=elapsed_ms,
                        http_status_code=200,
                        profile_url="https://www.snapchat.com",
                    )
            except Exception:
                pass

        if resp.status_code == 404:
            return self.create_result(
                target=target,
                status=DetectionStatus.NOT_FOUND,
                response_time_ms=elapsed_ms,
                http_status_code=404,
            )

        if resp.status_code in (403, 429):
            return self.create_result(
                target=target,
                status=DetectionStatus.BLOCKED if resp.status_code == 403 else DetectionStatus.RATE_LIMITED,
                response_time_ms=elapsed_ms,
                http_status_code=resp.status_code,
            )

        return self.create_result(
            target=target,
            status=DetectionStatus.ERROR,
            response_time_ms=elapsed_ms,
            http_status_code=resp.status_code,
            error_message="Ошибка запроса к Snapchat API",
        )


@EmailCheckerRegistry.register("microsoft")
class MicrosoftEmailChecker(BaseEmailChecker):
    """Проверка наличия учетной записи Microsoft / Live по email."""
    @property
    def name(self) -> str:
        return "Microsoft"

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        check_url = "https://login.live.com/GetCredentialType.srf"
        headers = self.default_headers.copy()
        headers.update({
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json",
            "Referer": "https://login.live.com/",
            "Origin": "https://login.live.com",
        })
        payload = {
            "username": email,
            "isOtherIdBPPlatform": True,
            "checkPhones": False,
            "isRemoteNGCSupported": True,
            "isCookieBannerShown": False,
            "isFidoSupported": True,
            "forceotclogin": False,
            "isExternalFederationDisallowed": False,
            "isRemoteConnectSupported": False,
            "federationFlags": 0,
            "isSignup": False,
            "flowToken": "",
        }
        resp = await client.post(check_url, json=payload, headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code == 200:
            try:
                data = resp.json()
                if data.get("ThrottleStatus") == 1:
                    return self.create_result(
                        target=target,
                        status=DetectionStatus.RATE_LIMITED,
                        response_time_ms=elapsed_ms,
                        http_status_code=200,
                        error_message="Microsoft API ограничил частоту запросов (ThrottleStatus=1)",
                    )
                if_exists = data.get("IfExistsResult")
                if if_exists == 0:
                    extracted = {}
                    if "UserTenantType" in data:
                        extracted["tenant_type"] = data["UserTenantType"]
                    return self.create_result(
                        target=target,
                        status=DetectionStatus.FOUND,
                        response_time_ms=elapsed_ms,
                        http_status_code=200,
                        profile_url="https://account.microsoft.com",
                        extracted_data=extracted,
                    )
                if if_exists == 1:
                    return self.create_result(
                        target=target,
                        status=DetectionStatus.NOT_FOUND,
                        response_time_ms=elapsed_ms,
                        http_status_code=200,
                    )
                if if_exists == 5:
                    return self.create_result(
                        target=target,
                        status=DetectionStatus.RATE_LIMITED,
                        response_time_ms=elapsed_ms,
                        http_status_code=200,
                        error_message="Превышен лимит запросов к Microsoft API (IfExistsResult=5)",
                    )
            except Exception:
                pass

        if resp.status_code in (403, 429):
            return self.create_result(
                target=target,
                status=DetectionStatus.BLOCKED if resp.status_code == 403 else DetectionStatus.RATE_LIMITED,
                response_time_ms=elapsed_ms,
                http_status_code=resp.status_code,
            )

        return self.create_result(
            target=target,
            status=DetectionStatus.ERROR,
            response_time_ms=elapsed_ms,
            http_status_code=resp.status_code,
            error_message="Некорректный ответ Microsoft API",
        )


@EmailCheckerRegistry.register("duolingo")
class DuolingoEmailChecker(BaseEmailChecker):
    """Проверка наличия учетной записи Duolingo по email."""
    @property
    def name(self) -> str:
        return "Duolingo"

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        api_url = f"https://www.duolingo.com/2017-06-30/users?email={quote(email)}"
        headers = self.default_headers.copy()
        headers.update({
            "Accept": "application/json",
            "Referer": "https://www.duolingo.com/",
        })
        resp = await client.get(api_url, headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code == 200:
            try:
                data = resp.json()
                users = data.get("users", [])
                if users:
                    u = users[0]
                    uname = u.get("username", "")
                    p_url = f"https://www.duolingo.com/profile/{uname}" if uname else "https://www.duolingo.com"
                    extracted: dict[str, object] = {}
                    if uname:
                        extracted["username"] = uname
                    if "name" in u and u["name"]:
                        extracted["display_name"] = u["name"]
                    if "learningLanguage" in u and u["learningLanguage"]:
                        extracted["learning_language"] = u["learningLanguage"]
                    if "picture" in u and u["picture"]:
                        extracted["avatar_url"] = u["picture"]

                    return self.create_result(
                        target=target,
                        status=DetectionStatus.FOUND,
                        response_time_ms=elapsed_ms,
                        http_status_code=200,
                        profile_url=p_url,
                        extracted_data=extracted,
                    )
                return self.create_result(
                    target=target,
                    status=DetectionStatus.NOT_FOUND,
                    response_time_ms=elapsed_ms,
                    http_status_code=200,
                )
            except Exception:
                pass

        if resp.status_code in (403, 429):
            return self.create_result(
                target=target,
                status=DetectionStatus.BLOCKED if resp.status_code == 403 else DetectionStatus.RATE_LIMITED,
                response_time_ms=elapsed_ms,
                http_status_code=resp.status_code,
            )

        return self.create_result(
            target=target,
            status=DetectionStatus.ERROR,
            response_time_ms=elapsed_ms,
            http_status_code=resp.status_code,
            error_message="Некорректный ответ Duolingo API",
        )


@EmailCheckerRegistry.register("gitlab")
class GitLabEmailChecker(BaseEmailChecker):
    """Проверка наличия учетной записи GitLab по email."""
    @property
    def name(self) -> str:
        return "GitLab"

    @property
    def is_active_probe(self) -> bool:
        return True

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        reset_new_url = "https://gitlab.com/users/password/new"
        reset_post_url = "https://gitlab.com/users/password"
        headers = self.default_headers.copy()

        resp_get = await client.get(reset_new_url, headers=headers)
        if resp_get.status_code != 200:
            elapsed = (time.monotonic() - start_time) * 1000
            return self.create_result(
                target=target,
                status=DetectionStatus.ERROR,
                response_time_ms=elapsed,
                http_status_code=resp_get.status_code,
                error_message="Не удалось загрузить форму сброса пароля GitLab",
            )

        token = self.extract_csrf(
            resp_get.text,
            r'name="authenticity_token"\s+value="([^"]+)"',
        )
        if not token:
            elapsed = (time.monotonic() - start_time) * 1000
            return self.create_result(
                target=target,
                status=DetectionStatus.BLOCKED,
                response_time_ms=elapsed,
                error_message="CSRF токен GitLab не найден",
            )

        post_headers = headers.copy()
        post_headers.update({
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://gitlab.com",
            "Referer": reset_new_url,
        })
        payload = {"authenticity_token": token, "user[email]": email}
        resp_post = await client.post(reset_post_url, content=urlencode(payload), headers=post_headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        text = resp_post.text.lower()
        if "not found" in text or "can't be blank" in text or resp_post.status_code == 422:
            return self.create_result(
                target=target,
                status=DetectionStatus.NOT_FOUND,
                response_time_ms=elapsed_ms,
                http_status_code=resp_post.status_code,
            )

        if resp_post.status_code in (200, 302):
            return self.create_result(
                target=target,
                status=DetectionStatus.FOUND,
                response_time_ms=elapsed_ms,
                http_status_code=resp_post.status_code,
                profile_url="https://gitlab.com",
            )

        if resp_post.status_code in (403, 429):
            return self.create_result(
                target=target,
                status=DetectionStatus.BLOCKED if resp_post.status_code == 403 else DetectionStatus.RATE_LIMITED,
                response_time_ms=elapsed_ms,
                http_status_code=resp_post.status_code,
            )

        return self.create_result(
            target=target,
            status=DetectionStatus.ERROR,
            response_time_ms=elapsed_ms,
            http_status_code=resp_post.status_code,
            error_message="Неоднозначный ответ сервиса сброса пароля GitLab",
        )


@EmailCheckerRegistry.register("mega")
class MegaEmailChecker(BaseEmailChecker):
    """Проверка наличия учетной записи Mega по email."""
    @property
    def name(self) -> str:
        return "Mega"

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        api_url = "https://g.api.mega.co.nz/cs?id=0"
        headers = self.default_headers.copy()
        headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin": "https://mega.nz",
            "Referer": "https://mega.nz/",
        })
        payload = [{"a": "us0", "user": email}]
        resp = await client.post(api_url, json=payload, headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list) and data:
                    item = data[0]
                    if isinstance(item, int):
                        if item in (-2, -9):
                            return self.create_result(
                                target=target,
                                status=DetectionStatus.NOT_FOUND,
                                response_time_ms=elapsed_ms,
                                http_status_code=200,
                            )
                    elif isinstance(item, dict):
                        return self.create_result(
                            target=target,
                            status=DetectionStatus.FOUND,
                            response_time_ms=elapsed_ms,
                            http_status_code=200,
                            profile_url="https://mega.nz",
                        )
            except Exception:
                pass

        if resp.status_code in (403, 429):
            return self.create_result(
                target=target,
                status=DetectionStatus.BLOCKED if resp.status_code == 403 else DetectionStatus.RATE_LIMITED,
                response_time_ms=elapsed_ms,
                http_status_code=resp.status_code,
            )

        return self.create_result(
            target=target,
            status=DetectionStatus.ERROR,
            response_time_ms=elapsed_ms,
            http_status_code=resp.status_code,
            error_message="Некорректный ответ Mega API",
        )


@EmailCheckerRegistry.register("protonmail")
class ProtonMailEmailChecker(BaseEmailChecker):
    """Проверка наличия учетной записи ProtonMail по публичному PGP-серверу."""
    @property
    def name(self) -> str:
        return "ProtonMail"

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        api_url = f"https://api.protonmail.ch/pks/lookup?op=index&search={quote(email)}"
        headers = self.default_headers.copy()
        headers.update({
            "Accept": "text/plain",
            "Origin": "https://proton.me",
        })
        resp = await client.get(api_url, headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code == 200:
            body = resp.text
            if "info:1:1" in body or "pub:" in body:
                return self.create_result(
                    target=target,
                    status=DetectionStatus.FOUND,
                    response_time_ms=elapsed_ms,
                    http_status_code=200,
                    profile_url="https://proton.me",
                )
            if "info:1:0" in body:
                return self.create_result(
                    target=target,
                    status=DetectionStatus.NOT_FOUND,
                    response_time_ms=elapsed_ms,
                    http_status_code=200,
                )

        if resp.status_code == 404:
            return self.create_result(
                target=target,
                status=DetectionStatus.NOT_FOUND,
                response_time_ms=elapsed_ms,
                http_status_code=404,
            )

        if resp.status_code in (403, 429):
            return self.create_result(
                target=target,
                status=DetectionStatus.BLOCKED if resp.status_code == 403 else DetectionStatus.RATE_LIMITED,
                response_time_ms=elapsed_ms,
                http_status_code=resp.status_code,
            )

        return self.create_result(
            target=target,
            status=DetectionStatus.ERROR,
            response_time_ms=elapsed_ms,
            http_status_code=resp.status_code,
            error_message="Некорректный ответ Proton API",
        )


@EmailCheckerRegistry.register("apple id")
class AppleEmailChecker(BaseEmailChecker):
    """Проверка наличия учетной записи Apple ID по email."""
    @property
    def name(self) -> str:
        return "Apple ID"

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        check_url = "https://appleid.apple.com/account/validation/appleid"
        headers = self.default_headers.copy()
        headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Origin": "https://appleid.apple.com",
            "Referer": "https://appleid.apple.com/account",
            "X-Requested-With": "XMLHttpRequest",
        })
        payload = {"appleId": email}
        resp = await client.post(check_url, json=payload, headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code == 409:
            return self.create_result(
                target=target,
                status=DetectionStatus.FOUND,
                response_time_ms=elapsed_ms,
                http_status_code=409,
                profile_url="https://appleid.apple.com",
            )

        if resp.status_code == 200:
            try:
                data = resp.json()
                is_used = data.get("used", False)
                is_valid = data.get("valid", True)
                if is_used is True or is_valid is False:
                    return self.create_result(
                        target=target,
                        status=DetectionStatus.FOUND,
                        response_time_ms=elapsed_ms,
                        http_status_code=200,
                        profile_url="https://appleid.apple.com",
                    )
                return self.create_result(
                    target=target,
                    status=DetectionStatus.NOT_FOUND,
                    response_time_ms=elapsed_ms,
                    http_status_code=200,
                )
            except Exception:
                pass

        if resp.status_code in (403, 429):
            return self.create_result(
                target=target,
                status=DetectionStatus.BLOCKED if resp.status_code == 403 else DetectionStatus.RATE_LIMITED,
                response_time_ms=elapsed_ms,
                http_status_code=resp.status_code,
            )

        return self.create_result(
            target=target,
            status=DetectionStatus.ERROR,
            response_time_ms=elapsed_ms,
            http_status_code=resp.status_code,
            error_message="Некорректный ответ Apple ID API",
        )


@EmailCheckerRegistry.register("atlassian")
class AtlassianEmailChecker(BaseEmailChecker):
    """Проверка наличия учетной записи Atlassian (Jira, Confluence, Trello)."""
    @property
    def name(self) -> str:
        return "Atlassian"

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        check_url = f"https://id.atlassian.com/rest/marketing-consent/config?email={quote(email)}"
        headers = self.default_headers.copy()
        headers.update({
            "Accept": "application/json",
            "Referer": "https://id.atlassian.com/login",
            "Origin": "https://id.atlassian.com",
        })
        resp = await client.get(check_url, headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code == 200:
            return self.create_result(
                target=target,
                status=DetectionStatus.FOUND,
                response_time_ms=elapsed_ms,
                http_status_code=200,
                profile_url="https://id.atlassian.com",
            )

        if resp.status_code == 404:
            return self.create_result(
                target=target,
                status=DetectionStatus.NOT_FOUND,
                response_time_ms=elapsed_ms,
                http_status_code=404,
            )

        if resp.status_code in (403, 429):
            return self.create_result(
                target=target,
                status=DetectionStatus.BLOCKED if resp.status_code == 403 else DetectionStatus.RATE_LIMITED,
                response_time_ms=elapsed_ms,
                http_status_code=resp.status_code,
            )

        return self.create_result(
            target=target,
            status=DetectionStatus.ERROR,
            response_time_ms=elapsed_ms,
            http_status_code=resp.status_code,
            error_message="Некорректный ответ Atlassian API",
        )


@EmailCheckerRegistry.register("pinterest")
class PinterestEmailChecker(BaseEmailChecker):
    """Проверка наличия учетной записи Pinterest по email."""
    @property
    def name(self) -> str:
        return "Pinterest"

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        data_param = json.dumps({"options": {"email": email}})
        check_url = f"https://www.pinterest.com/resource/EmailExistsResource/get/?data={quote(data_param)}"
        headers = self.default_headers.copy()
        headers.update({
            "Accept": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": "https://www.pinterest.com/",
        })
        resp = await client.get(check_url, headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code == 200:
            try:
                res_json = resp.json()
                exists = res_json.get("resource_response", {}).get("data")
                if exists is True:
                    return self.create_result(
                        target=target,
                        status=DetectionStatus.FOUND,
                        response_time_ms=elapsed_ms,
                        http_status_code=200,
                        profile_url="https://www.pinterest.com",
                    )
                if exists is False:
                    return self.create_result(
                        target=target,
                        status=DetectionStatus.NOT_FOUND,
                        response_time_ms=elapsed_ms,
                        http_status_code=200,
                    )
            except Exception:
                pass

        if resp.status_code in (403, 429):
            return self.create_result(
                target=target,
                status=DetectionStatus.BLOCKED if resp.status_code == 403 else DetectionStatus.RATE_LIMITED,
                response_time_ms=elapsed_ms,
                http_status_code=resp.status_code,
            )

        return self.create_result(
            target=target,
            status=DetectionStatus.ERROR,
            response_time_ms=elapsed_ms,
            http_status_code=resp.status_code,
            error_message="Некорректный ответ Pinterest API",
        )


@EmailCheckerRegistry.register("olx")
class OlxEmailChecker(BaseEmailChecker):
    """Проверка наличия учетной записи на доске объявлений OLX."""
    @property
    def name(self) -> str:
        return "OLX"

    @property
    def is_active_probe(self) -> bool:
        return True

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        check_url = "https://www.olx.ua/api/v1/auth/forgot-password/"
        headers = self.default_headers.copy()
        headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin": "https://www.olx.ua",
            "Referer": "https://www.olx.ua/",
        })
        payload = {"email": email}
        resp = await client.post(check_url, json=payload, headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code in (200, 204):
            return self.create_result(
                target=target,
                status=DetectionStatus.FOUND,
                response_time_ms=elapsed_ms,
                http_status_code=resp.status_code,
                profile_url="https://www.olx.ua",
            )

        if resp.status_code == 404 or (resp.status_code == 400 and "not_found" in resp.text.lower()):
            return self.create_result(
                target=target,
                status=DetectionStatus.NOT_FOUND,
                response_time_ms=elapsed_ms,
                http_status_code=resp.status_code,
            )

        if resp.status_code in (403, 429):
            return self.create_result(
                target=target,
                status=DetectionStatus.BLOCKED if resp.status_code == 403 else DetectionStatus.RATE_LIMITED,
                response_time_ms=elapsed_ms,
                http_status_code=resp.status_code,
            )

        return self.create_result(
            target=target,
            status=DetectionStatus.ERROR,
            response_time_ms=elapsed_ms,
            http_status_code=resp.status_code,
            error_message="Некорректный ответ OLX API",
        )


@EmailCheckerRegistry.register("docker hub")
class DockerEmailChecker(BaseEmailChecker):
    """Проверка наличия учетной записи на Docker Hub по email."""
    @property
    def name(self) -> str:
        return "Docker Hub"

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        check_url = "https://hub.docker.com/v2/users/"
        headers = self.default_headers.copy()
        headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin": "https://hub.docker.com",
            "Referer": "https://hub.docker.com/signup",
        })
        dummy_uname = f"chk_{int(time.time())}"
        payload = {"username": dummy_uname, "email": email, "password": "DummyPassword123!@#"}
        resp = await client.post(check_url, json=payload, headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code == 400:
            text = resp.text.lower()
            if "already in use" in text or "already exists" in text or "unique" in text or "email is taken" in text:
                return self.create_result(
                    target=target,
                    status=DetectionStatus.FOUND,
                    response_time_ms=elapsed_ms,
                    http_status_code=400,
                    profile_url="https://hub.docker.com",
                )
            return self.create_result(
                target=target,
                status=DetectionStatus.NOT_FOUND,
                response_time_ms=elapsed_ms,
                http_status_code=400,
            )

        if resp.status_code == 201:
            return self.create_result(
                target=target,
                status=DetectionStatus.NOT_FOUND,
                response_time_ms=elapsed_ms,
                http_status_code=201,
            )

        if resp.status_code in (403, 429):
            return self.create_result(
                target=target,
                status=DetectionStatus.BLOCKED if resp.status_code == 403 else DetectionStatus.RATE_LIMITED,
                response_time_ms=elapsed_ms,
                http_status_code=resp.status_code,
            )

        return self.create_result(
            target=target,
            status=DetectionStatus.ERROR,
            response_time_ms=elapsed_ms,
            http_status_code=resp.status_code,
            error_message="Некорректный ответ Docker Hub API",
        )


# ==============================================================================
# Оркестратор EmailReconExecutor
# ==============================================================================

class EmailReconExecutor:
    """Оркестратор параллельной проверки eMail через Google и сервис-чекеры."""

    def __init__(
        self,
        event_queue: Optional[asyncio.Queue[Any]] = None,
        engine: Optional["ScanEngine"] = None,
        dispatcher: Optional[ReportDispatcher] = None,
        passive_mode: bool = True,
    ) -> None:
        self.event_queue = event_queue or asyncio.Queue()
        self.dispatcher = dispatcher or ReportDispatcher()
        self.passive_mode = passive_mode
        if engine is None:
            from epitaph.core.engine import ScanEngine
            self.engine = ScanEngine(event_queue=self.event_queue, dispatcher=self.dispatcher)
        else:
            self.engine = engine

        self.google_checker = GoogleAccountChecker()

    async def run_search(
        self,
        target: TargetProfile,
        output_dir: Optional[Path] = None,
    ) -> ScanSessionResult:
        # Нормализация email-адреса цели
        raw_email = target.username.strip().lower()
        if "@" not in raw_email:
            raw_email = f"{raw_email}@gmail.com"
        target = TargetProfile(username=raw_email, metadata=target.metadata)

        # OPSEC-03: Проверка готовности прокси-пула перед запуском конкурентных задач
        if getattr(self.engine.scheduler, "enforce_proxy", False):
            pm = getattr(self.engine.scheduler, "proxy_manager", None)
            if pm is not None and hasattr(pm, "has_available_proxies"):
                if not await pm.has_available_proxies():
                    raise RuntimeError("OPSEC Fail-Closed: Пул прокси истощен при enforce_proxy. Сканирование eMail заблокировано.")

        # Загрузка актуальных инстансов чекеров из реестра
        email_checkers = EmailCheckerRegistry.get_all_instances()

        # OPSEC-02: Фильтрация активных триггерных чекеров в пассивном режиме (защита от target tipping-off)
        active_checkers = []
        for checker in email_checkers:
            if self.passive_mode and getattr(checker, "is_active_probe", False):
                await self.event_queue.put(
                    LogEvent(
                        message=f"[ OPSEC Passive ] Пропуск активного чекера {checker.name} (риск уведомления цели)",
                        level="DEBUG",
                    )
                )
                continue
            active_checkers.append(checker)

        session_id = uuid.uuid4().hex[:8]
        start_time = datetime.now(timezone.utc)
        total_checks = 1 + len(active_checkers)

        await self.event_queue.put(StartScanEvent(target=target, session_id=session_id))
        mode_desc = "пассивный" if self.passive_mode else "полный"
        await self.event_queue.put(
            LogEvent(
                message=f"Запуск разведки по eMail ({mode_desc} режим, {total_checks} модулей): {target.username}...",
                level="INFO",
            )
        )

        completed_count = 0
        all_results: List[CheckResult] = []

        async def _run_single(checker_instance: Any) -> None:
            nonlocal completed_count
            try:
                res = await self.engine.scheduler.run_checker(checker_instance, target)
            except Exception as exc:
                res = CheckResult(
                    platform_name=getattr(checker_instance, "name", "Unknown"),
                    target=target,
                    status=DetectionStatus.ERROR,
                    response_time_ms=0.0,
                    error_message=f"Сбой выполнения чекера: {exc}",
                )
            all_results.append(res)
            completed_count += 1
            await self.event_queue.put(CheckResultEvent(result=res))
            await self.event_queue.put(
                ProgressUpdateEvent(completed=completed_count, total=total_checks)
            )

        async with asyncio.TaskGroup() as tg:
            tg.create_task(_run_single(self.google_checker))
            for checker in active_checkers:
                tg.create_task(_run_single(checker))

        session_result = ScanSessionResult(
            session_id=session_id,
            target=target,
            start_time=start_time,
            end_time=datetime.now(timezone.utc),
            results=all_results,
        )

        target_out = output_dir or get_default_report_dir(session_id, target.username)
        reports = await self.dispatcher.export_all(session_result, target_out)
        await self.event_queue.put(
            ScanCompletedEvent(session_id=session_id, report_paths=reports)
        )

        return session_result
