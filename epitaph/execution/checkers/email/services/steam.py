"""Модуль проверки существования аккаунта в Steam по email."""
from __future__ import annotations

import time
from urllib.parse import urlencode
import httpx

from epitaph.execution.checkers.email.base import BaseEmailChecker
from epitaph.execution.checkers.email.registry import EmailCheckerRegistry
from epitaph.models.base import DetectionStatus
from epitaph.models.result import CheckResult
from epitaph.models.target import TargetProfile


@EmailCheckerRegistry.register("steam")
class SteamEmailChecker(BaseEmailChecker):
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
            error_message="Сбой проверки Steam checkemail API",
        )
