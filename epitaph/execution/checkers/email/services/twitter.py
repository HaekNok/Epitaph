"""Модуль проверки существования аккаунта в Twitter / X по email."""
from __future__ import annotations

import time
import httpx

from epitaph.execution.checkers.email.base import BaseEmailChecker
from epitaph.execution.checkers.email.registry import EmailCheckerRegistry
from epitaph.models.base import DetectionStatus
from epitaph.models.result import CheckResult
from epitaph.models.target import TargetProfile


@EmailCheckerRegistry.register("twitter")
class TwitterEmailChecker(BaseEmailChecker):
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
        api_url = f"https://api.twitter.com/i/users/email_available.json?email={email}"
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
            # taken: true -> аккаунт с таким email уже зарегистрирован
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
