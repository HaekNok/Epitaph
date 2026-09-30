"""Базовый абстрактный класс для модулей проверки регистрации email."""
from __future__ import annotations

from abc import abstractmethod
import re
import time
from typing import Dict, Final, Optional, Pattern

import httpx

from epitaph.execution.base import BasePlatformChecker
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.result import CheckResult
from epitaph.models.target import TargetProfile

# RFC 5322 совместимое регулярное выражение для предварительной валидации
EMAIL_REGEX: Final[Pattern[str]] = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)


class BaseEmailChecker(BasePlatformChecker):
    """Абстрактный контракт для проверки наличия учетной записи по email."""

    @property
    def execution_type(self) -> ExecutionType:
        return ExecutionType.HTTP

    @property
    def rate_limit_delay(self) -> float:
        # Базовая задержка между запросами к домену для предотвращения 429
        return 0.5

    @property
    def default_headers(self) -> Dict[str, str]:
        return {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Ch-Ua": '"Not/A)Brand";v="8", "Chromium";v="126"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Linux"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }

    def sanitize_email(self, raw_email: str) -> str:
        """Валидация и нормализация email-адреса для защиты от инъекций."""
        cleaned = raw_email.strip().lower()
        if not EMAIL_REGEX.match(cleaned):
            raise ValueError(f"Некорректный формат email-адреса: {raw_email}")
        return cleaned

    def extract_csrf(
        self,
        html_content: str,
        regex_pattern: str,
        group_index: int = 1,
    ) -> Optional[str]:
        """Извлечение CSRF-токена из тела HTML через регулярное выражение."""
        match = re.search(regex_pattern, html_content)
        if match and len(match.groups()) >= group_index:
            return match.group(group_index)
        return None

    def create_result(
        self,
        target: TargetProfile,
        status: DetectionStatus,
        response_time_ms: float,
        profile_url: Optional[str] = None,
        http_status_code: Optional[int] = None,
        extracted_data: Optional[Dict[str, object]] = None,
        error_message: Optional[str] = None,
    ) -> CheckResult:
        """Вспомогательный конструктор иммутабельного объекта CheckResult."""
        return CheckResult(
            platform_name=self.name,
            target=target,
            status=status,
            profile_url=profile_url,
            response_time_ms=max(0.0, response_time_ms),
            execution_type=self.execution_type,
            http_status_code=http_status_code,
            extracted_data=extracted_data or {},
            error_message=error_message,
        )

    async def check_http(
        self,
        target: TargetProfile,
        client: httpx.AsyncClient,
    ) -> CheckResult:
        """Реализация вызова check_http с автоматическим замером задержки."""
        start_time = time.monotonic()
        try:
            clean_email = self.sanitize_email(target.username)
            return await self.probe_email(clean_email, target, client, start_time)
        except ValueError as val_err:
            elapsed_ms = (time.monotonic() - start_time) * 1000
            return self.create_result(
                target=target,
                status=DetectionStatus.ERROR,
                response_time_ms=elapsed_ms,
                error_message=str(val_err),
            )
        except httpx.TimeoutException:
            elapsed_ms = (time.monotonic() - start_time) * 1000
            return self.create_result(
                target=target,
                status=DetectionStatus.ERROR,
                response_time_ms=elapsed_ms,
                error_message="Сетевой таймаут при проверке сервиса",
            )
        except httpx.HTTPStatusError as http_err:
            elapsed_ms = (time.monotonic() - start_time) * 1000
            if http_err.response.status_code == 429:
                return self.create_result(
                    target=target,
                    status=DetectionStatus.RATE_LIMITED,
                    response_time_ms=elapsed_ms,
                    http_status_code=429,
                    error_message="Превышен лимит запросов к сервису",
                )
            if http_err.response.status_code == 403:
                return self.create_result(
                    target=target,
                    status=DetectionStatus.BLOCKED,
                    response_time_ms=elapsed_ms,
                    http_status_code=403,
                    error_message="Доступ заблокирован (Cloudflare / WAF)",
                )
            return self.create_result(
                target=target,
                status=DetectionStatus.ERROR,
                response_time_ms=elapsed_ms,
                http_status_code=http_err.response.status_code,
                error_message=f"HTTP ошибка: {http_err.response.status_code}",
            )
        except Exception as exc:
            elapsed_ms = (time.monotonic() - start_time) * 1000
            return self.create_result(
                target=target,
                status=DetectionStatus.ERROR,
                response_time_ms=elapsed_ms,
                error_message=f"Непредвиденный сбой проверки: {type(exc).__name__}",
            )

    @abstractmethod
    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        """Индивидуальная логика проверки email-адреса на целевой платформе."""
        raise NotImplementedError

    async def check_browser(
        self,
        target: TargetProfile,
        context: object,
    ) -> CheckResult:
        """Email-чекеры работают исключительно через легковесный асинхронный HTTP-стек."""
        raise NotImplementedError("Browser execution is disabled for Email Checkers.")
