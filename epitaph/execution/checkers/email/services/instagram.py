"""Модуль проверки регистрации email в Instagram."""
from __future__ import annotations

import time
import httpx

from epitaph.execution.checkers.email.base import BaseEmailChecker
from epitaph.execution.checkers.email.registry import EmailCheckerRegistry
from epitaph.models.base import DetectionStatus
from epitaph.models.result import CheckResult
from epitaph.models.target import TargetProfile


@EmailCheckerRegistry.register("instagram")
class InstagramEmailChecker(BaseEmailChecker):
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

        # Шаг 1: Первичный запрос для установки сессии и получения csrftoken в cookie
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

        # Шаг 2: Проверка почты через внутренний API регистрации
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
            # email_is_taken: true -> аккаунт зарегистрирован
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
