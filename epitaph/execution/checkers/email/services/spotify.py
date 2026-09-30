"""Модуль проверки существования аккаунта в Spotify по email."""
from __future__ import annotations

import time
import httpx

from epitaph.execution.checkers.email.base import BaseEmailChecker
from epitaph.execution.checkers.email.registry import EmailCheckerRegistry
from epitaph.models.base import DetectionStatus
from epitaph.models.result import CheckResult
from epitaph.models.target import TargetProfile


@EmailCheckerRegistry.register("spotify")
class SpotifyEmailChecker(BaseEmailChecker):
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
        api_url = f"https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={email}"
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
            # status: 1 -> почта свободна (аккаунт НЕ существует)
            # status: 20 -> почта занята (аккаунт существует)
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
