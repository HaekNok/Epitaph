"""Модуль проверки существования аккаунта в Discord по email."""
from __future__ import annotations

import time
import httpx

from epitaph.execution.checkers.email.base import BaseEmailChecker
from epitaph.execution.checkers.email.registry import EmailCheckerRegistry
from epitaph.models.base import DetectionStatus
from epitaph.models.result import CheckResult
from epitaph.models.target import TargetProfile


@EmailCheckerRegistry.register("discord")
class DiscordEmailChecker(BaseEmailChecker):
    @property
    def name(self) -> str:
        return "Discord"

    @property
    def is_active_probe(self) -> bool:
        """Маркер активной проверки: сброс пароля отправляет email уведомление цели."""
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
