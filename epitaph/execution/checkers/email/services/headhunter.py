"""Модуль проверки существования аккаунта на платформе Headhunter по email."""
from __future__ import annotations

import time
from urllib.parse import quote
import httpx

from epitaph.execution.checkers.email.base import BaseEmailChecker
from epitaph.execution.checkers.email.registry import EmailCheckerRegistry
from epitaph.models.base import DetectionStatus
from epitaph.models.result import CheckResult
from epitaph.models.target import TargetProfile


@EmailCheckerRegistry.register("headhunter")
class HeadhunterEmailChecker(BaseEmailChecker):
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
        encoded_login = quote(email)
        check_url = f"https://hh.ru/account/check_login?login={encoded_login}"
        headers = self.default_headers.copy()
        headers.update({
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": "https://hh.ru/account/login",
        })

        resp = await client.get(check_url, headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code == 200:
            try:
                data = resp.json()
                if data.get("is_used") is True:
                    return self.create_result(
                        target=target,
                        status=DetectionStatus.FOUND,
                        response_time_ms=elapsed_ms,
                        http_status_code=200,
                        profile_url="https://hh.ru",
                    )
                if data.get("is_used") is False:
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
            error_message="Нестандартный ответ Headhunter check_login API",
        )
