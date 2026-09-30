"""Модуль проверки существования аккаунта в TikTok по email."""
from __future__ import annotations

import time
from urllib.parse import urlencode
import httpx

from epitaph.execution.checkers.email.base import BaseEmailChecker
from epitaph.execution.checkers.email.registry import EmailCheckerRegistry
from epitaph.models.base import DetectionStatus
from epitaph.models.result import CheckResult
from epitaph.models.target import TargetProfile


@EmailCheckerRegistry.register("tiktok")
class TikTokEmailChecker(BaseEmailChecker):
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
        query_params = urlencode({"email": email, "aid": "1988"})
        api_url = f"https://www.tiktok.com/passport/web/check_email_registered/?{query_params}"
        headers = self.default_headers.copy()
        headers.update({
            "Accept": "application/json, text/plain, */*",
            "Referer": "https://www.tiktok.com/signup",
        })

        resp = await client.get(api_url, headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code == 200:
            try:
                data = resp.json()
                reg_flag = data.get("data", {}).get("is_registered")
                if reg_flag in (1, True):
                    return self.create_result(
                        target=target,
                        status=DetectionStatus.FOUND,
                        response_time_ms=elapsed_ms,
                        http_status_code=200,
                        profile_url="https://www.tiktok.com",
                    )
                if reg_flag in (0, False):
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
            error_message="Нестандартный ответ TikTok Passport API",
        )
