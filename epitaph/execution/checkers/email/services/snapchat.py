"""Модуль проверки существования аккаунта в Snapchat по email."""
from __future__ import annotations

import time
import httpx

from epitaph.execution.checkers.email.base import BaseEmailChecker
from epitaph.execution.checkers.email.registry import EmailCheckerRegistry
from epitaph.models.base import DetectionStatus
from epitaph.models.result import CheckResult
from epitaph.models.target import TargetProfile


@EmailCheckerRegistry.register("snapchat")
class SnapchatEmailChecker(BaseEmailChecker):
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
            "Referer": "https://accounts.snapchat.com/",
        })
        payload = {"email": email}

        resp = await client.post(api_url, json=payload, headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code == 200:
            return self.create_result(
                target=target,
                status=DetectionStatus.FOUND,
                response_time_ms=elapsed_ms,
                http_status_code=200,
                profile_url="https://www.snapchat.com",
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
            error_message="Сбой проверки Snapchat Bitmoji API",
        )
