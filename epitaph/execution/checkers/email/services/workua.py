"""Модуль проверки существования аккаунта на портале Work.ua по email."""
from __future__ import annotations

import time
from urllib.parse import urlencode
import httpx

from epitaph.execution.checkers.email.base import BaseEmailChecker
from epitaph.execution.checkers.email.registry import EmailCheckerRegistry
from epitaph.models.base import DetectionStatus
from epitaph.models.result import CheckResult
from epitaph.models.target import TargetProfile


@EmailCheckerRegistry.register("work_ua")
class WorkUaEmailChecker(BaseEmailChecker):
    @property
    def name(self) -> str:
        return "Work.ua"

    @property
    def is_active_probe(self) -> bool:
        """Маркер активной проверки: отправка запроса в /pass/ может инициировать письмо сброса."""
        return True

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        reset_url = "https://www.work.ua/pass/"
        headers = self.default_headers.copy()
        headers.update({
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://www.work.ua",
            "Referer": "https://www.work.ua/pass/",
        })
        payload = {"email": email}

        resp = await client.post(reset_url, content=urlencode(payload), headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code == 302:
            return self.create_result(
                target=target,
                status=DetectionStatus.FOUND,
                response_time_ms=elapsed_ms,
                http_status_code=302,
                profile_url="https://www.work.ua",
            )

        if resp.status_code == 200:
            text = resp.text
            if "не знайдено" in text or "Користувача з такою електронною поштою не знайдено" in text:
                return self.create_result(
                    target=target,
                    status=DetectionStatus.NOT_FOUND,
                    response_time_ms=elapsed_ms,
                    http_status_code=200,
                )
            if "Лист для відновлення" in text or "відправлено" in text:
                return self.create_result(
                    target=target,
                    status=DetectionStatus.FOUND,
                    response_time_ms=elapsed_ms,
                    http_status_code=200,
                    profile_url="https://www.work.ua",
                )
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
            error_message="Сбой проверки формы восстановления Work.ua",
        )
