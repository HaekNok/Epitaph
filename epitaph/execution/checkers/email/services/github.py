"""Модуль проверки существования аккаунта на GitHub по email."""
from __future__ import annotations

import time
from urllib.parse import urlencode
import httpx

from epitaph.execution.checkers.email.base import BaseEmailChecker
from epitaph.execution.checkers.email.registry import EmailCheckerRegistry
from epitaph.models.base import DetectionStatus
from epitaph.models.result import CheckResult
from epitaph.models.target import TargetProfile


@EmailCheckerRegistry.register("github")
class GitHubEmailChecker(BaseEmailChecker):
    @property
    def name(self) -> str:
        return "GitHub"

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        reset_page_url = "https://github.com/password_reset"
        headers = self.default_headers.copy()

        # Шаг 1: GET-запрос для получения сессионных cookie и authenticity_token
        resp_get = await client.get(reset_page_url, headers=headers)
        if resp_get.status_code != 200:
            elapsed = (time.monotonic() - start_time) * 1000
            return self.create_result(
                target=target,
                status=DetectionStatus.ERROR,
                response_time_ms=elapsed,
                http_status_code=resp_get.status_code,
                error_message="Не удалось загрузить страницу password_reset",
            )

        token = self.extract_csrf(
            resp_get.text,
            r'name="authenticity_token"\s+value="([^"]+)"',
        )
        if not token:
            elapsed = (time.monotonic() - start_time) * 1000
            return self.create_result(
                target=target,
                status=DetectionStatus.BLOCKED,
                response_time_ms=elapsed,
                error_message="CSRF токен authenticity_token не найден в разметке",
            )

        # Шаг 2: Отправка probe POST-запроса
        post_headers = headers.copy()
        post_headers.update({
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://github.com",
            "Referer": reset_page_url,
        })
        payload = {"authenticity_token": token, "email": email}

        resp_post = await client.post(
            reset_page_url,
            content=urlencode(payload),
            headers=post_headers,
        )
        elapsed_ms = (time.monotonic() - start_time) * 1000

        # На GitHub: если почта не зарегистрирована, возвращается текст ошибки
        if "Can't find that email" in resp_post.text or "not found" in resp_post.text:
            return self.create_result(
                target=target,
                status=DetectionStatus.NOT_FOUND,
                response_time_ms=elapsed_ms,
                http_status_code=resp_post.status_code,
            )

        # Если произошел редирект или сообщение об отправке письма — аккаунт существует
        if resp_post.status_code in (200, 302):
            return self.create_result(
                target=target,
                status=DetectionStatus.FOUND,
                response_time_ms=elapsed_ms,
                http_status_code=resp_post.status_code,
                profile_url="https://github.com",
            )

        return self.create_result(
            target=target,
            status=DetectionStatus.ERROR,
            response_time_ms=elapsed_ms,
            http_status_code=resp_post.status_code,
            error_message="Неоднозначный ответ сервиса сброса пароля GitHub",
        )
