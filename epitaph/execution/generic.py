# Обобщенный data-driven чекер для декларативной проверки профилей
import re
import time
from typing import Any, Dict, Optional
from urllib.parse import urlparse
import httpx

from epitaph.execution.base import BasePlatformChecker
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.result import CheckResult
from epitaph.models.site import CheckType, SiteDefinition
from epitaph.models.target import TargetProfile


class GenericPlatformChecker(BasePlatformChecker):
    # Универсальный исполнитель проверок на основе спецификации SiteDefinition

    def __init__(self, site: SiteDefinition) -> None:
        self.site = site
        self._compiled_regex: Optional[re.Pattern[str]] = None
        if site.regex_check:
            try:
                self._compiled_regex = re.compile(site.regex_check)
            except re.error:
                self._compiled_regex = None

    @property
    def name(self) -> str:
        # Наименование платформы
        return self.site.name

    @property
    def domain(self) -> str:
        # Домен сервиса для группировки лимитов частоты запросов
        parsed = urlparse(self.site.url)
        return parsed.netloc.lower() or self.site.name.lower()

    @property
    def execution_type(self) -> ExecutionType:
        # Тип выполнения проверки
        return ExecutionType.HTTP

    @property
    def rate_limit_delay(self) -> float:
        # Задержка между запросами к домену
        return self.site.rate_limit_delay

    @property
    def headers(self) -> Dict[str, str]:
        # Пользовательские HTTP-заголовки
        base_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        }
        base_headers.update(self.site.headers)
        return base_headers

    async def check_browser(self, target: TargetProfile, context: Any) -> CheckResult:
        # Декларативные чекеры выполняются в чистом асинхронном HTTP-режиме
        return CheckResult(
            platform_name=self.name,
            target=target,
            status=DetectionStatus.BLOCKED,
            execution_type=self.execution_type,
            error_message="GenericPlatformChecker поддерживает только HTTP-проверку.",
        )

    async def check_http(
        self,
        target: TargetProfile,
        client: httpx.AsyncClient,
    ) -> CheckResult:
        # Выполнение HTTP-проверки по правилам SiteDefinition
        if self._compiled_regex and not self._compiled_regex.search(target.username):
            # Пропуск запроса при невалидном синтаксисе никнейма для платформы
            return CheckResult(
                platform_name=self.name,
                target=target,
                status=DetectionStatus.NOT_FOUND,
                profile_url=None,
                response_time_ms=0.0,
                execution_type=self.execution_type,
            )

        probe_url = (self.site.url_probe or self.site.url).replace("{username}", target.username)
        profile_url = self.site.url.replace("{username}", target.username)

        start_time = time.perf_counter()
        try:
            response = await client.get(
                probe_url,
                headers=self.headers,
                follow_redirects=True,
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            status = self._evaluate_response(response)
            detected_url = profile_url if status == DetectionStatus.FOUND else None

            return CheckResult(
                platform_name=self.name,
                target=target,
                status=status,
                profile_url=detected_url,
                response_time_ms=elapsed_ms,
                execution_type=self.execution_type,
                http_status_code=response.status_code,
            )
        except (httpx.ConnectTimeout, httpx.ReadTimeout) as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return CheckResult(
                platform_name=self.name,
                target=target,
                status=DetectionStatus.ERROR,
                response_time_ms=elapsed_ms,
                execution_type=self.execution_type,
                error_message=f"Timeout: {exc}",
            )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return CheckResult(
                platform_name=self.name,
                target=target,
                status=DetectionStatus.ERROR,
                response_time_ms=elapsed_ms,
                execution_type=self.execution_type,
                error_message=f"Request error: {type(exc).__name__} {exc}",
            )

    def _evaluate_response(self, response: httpx.Response) -> DetectionStatus:
        # Анализ HTTP-ответа в соответствии с check_type
        if response.status_code == 429:
            return DetectionStatus.RATE_LIMITED
        if response.status_code in (401, 403):
            return DetectionStatus.BLOCKED

        check_type = self.site.check_type

        if check_type == CheckType.STATUS_CODE:
            expected_err = self.site.error_code or 404
            if response.status_code == expected_err:
                return DetectionStatus.NOT_FOUND
            if 200 <= response.status_code < 300:
                return DetectionStatus.FOUND
            return DetectionStatus.NOT_FOUND

        if check_type == CheckType.MESSAGE:
            if response.status_code == (self.site.error_code or 404):
                return DetectionStatus.NOT_FOUND
            body = response.text
            if self.site.error_message and self.site.error_message in body:
                return DetectionStatus.NOT_FOUND
            for absence in self.site.absence_strings:
                if absence in body:
                    return DetectionStatus.NOT_FOUND
            if self.site.presence_strings:
                for presence in self.site.presence_strings:
                    if presence in body:
                        return DetectionStatus.FOUND
                return DetectionStatus.NOT_FOUND
            if 200 <= response.status_code < 300:
                return DetectionStatus.FOUND
            return DetectionStatus.NOT_FOUND

        if check_type == CheckType.RESPONSE_URL:
            if self.site.error_url and self.site.error_url in str(response.url):
                return DetectionStatus.NOT_FOUND
            if response.status_code == (self.site.error_code or 404):
                return DetectionStatus.NOT_FOUND
            if 200 <= response.status_code < 300:
                return DetectionStatus.FOUND
            return DetectionStatus.NOT_FOUND

        return DetectionStatus.UNKNOWN
