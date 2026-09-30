"""Модуль проверки существования аккаунта на портале Robota.ua по email."""
from __future__ import annotations

import time
import httpx

from epitaph.execution.checkers.email.base import BaseEmailChecker
from epitaph.execution.checkers.email.registry import EmailCheckerRegistry
from epitaph.models.base import DetectionStatus
from epitaph.models.result import CheckResult
from epitaph.models.target import TargetProfile


@EmailCheckerRegistry.register("robota_ua")
class RobotaUaEmailChecker(BaseEmailChecker):
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
            "Content-Type": "application/json",
            "Origin": "https://robota.ua",
            "Referer": "https://robota.ua/",
            "Accept": "application/json, text/plain, */*",
        })
        payload = {"email": email}

        resp = await client.post(check_url, json=payload, headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code == 200:
            try:
                data = resp.json()
                if data.get("exists") is True or data.get("isRegistered") is True or data.get("accountType"):
                    return self.create_result(
                        target=target,
                        status=DetectionStatus.FOUND,
                        response_time_ms=elapsed_ms,
                        http_status_code=200,
                        profile_url="https://robota.ua",
                    )
                if data.get("exists") is False or data.get("isRegistered") is False:
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
            error_message="Сбой проверки Robota.ua API",
        )
