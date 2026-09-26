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
    def __init__(self, site: SiteDefinition) -> None:
        self.site = site
        self._regex = re.compile(site.regex_check) if site.regex_check else None

    @property
    def name(self) -> str:
        return self.site.name

    @property
    def domain(self) -> str:
        return urlparse(self.site.url).netloc.lower() or self.site.name.lower()

    @property
    def execution_type(self) -> ExecutionType:
        return ExecutionType.HTTP

    @property
    def rate_limit_delay(self) -> float:
        return self.site.rate_limit_delay

    @property
    def headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        }
        headers.update(self.site.headers)
        return headers

    async def check_browser(self, target: TargetProfile, context: Any) -> CheckResult:
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
        # Пропуск запроса при несовпадении с правилами допустимых имен сервиса
        if self._regex and not self._regex.search(target.username):
            return CheckResult(
                platform_name=self.name,
                target=target,
                status=DetectionStatus.NOT_FOUND,
                execution_type=self.execution_type,
            )

        probe_url = (self.site.url_probe or self.site.url).replace("{username}", target.username)
        profile_url = self.site.url.replace("{username}", target.username)

        start = time.perf_counter()
        try:
            res = await client.get(probe_url, headers=self.headers, follow_redirects=True)
            elapsed = (time.perf_counter() - start) * 1000.0
            status = self._evaluate_status(res)
            return CheckResult(
                platform_name=self.name,
                target=target,
                status=status,
                profile_url=profile_url if status == DetectionStatus.FOUND else None,
                response_time_ms=elapsed,
                execution_type=self.execution_type,
                http_status_code=res.status_code,
            )
        except (httpx.ConnectTimeout, httpx.ReadTimeout) as err:
            return CheckResult(
                platform_name=self.name,
                target=target,
                status=DetectionStatus.ERROR,
                response_time_ms=(time.perf_counter() - start) * 1000.0,
                execution_type=self.execution_type,
                error_message=f"Timeout: {err}",
            )
        except Exception as err:
            return CheckResult(
                platform_name=self.name,
                target=target,
                status=DetectionStatus.ERROR,
                response_time_ms=(time.perf_counter() - start) * 1000.0,
                execution_type=self.execution_type,
                error_message=f"{type(err).__name__}: {err}",
            )

    def _evaluate_status(self, res: httpx.Response) -> DetectionStatus:
        if res.status_code == 429:
            return DetectionStatus.RATE_LIMITED
        if res.status_code in (401, 403):
            return DetectionStatus.BLOCKED

        err_code = self.site.error_code or 404
        if self.site.check_type == CheckType.STATUS_CODE:
            if res.status_code == err_code:
                return DetectionStatus.NOT_FOUND
            return DetectionStatus.FOUND if 200 <= res.status_code < 300 else DetectionStatus.NOT_FOUND

        if self.site.check_type == CheckType.RESPONSE_URL:
            if self.site.error_url and self.site.error_url in str(res.url):
                return DetectionStatus.NOT_FOUND
            if res.status_code == err_code:
                return DetectionStatus.NOT_FOUND
            return DetectionStatus.FOUND if 200 <= res.status_code < 300 else DetectionStatus.NOT_FOUND

        if self.site.check_type == CheckType.MESSAGE:
            if res.status_code == err_code:
                return DetectionStatus.NOT_FOUND
            body = res.text
            if (self.site.error_message and self.site.error_message in body) or any(s in body for s in self.site.absence_strings):
                return DetectionStatus.NOT_FOUND
            if self.site.presence_strings and not any(s in body for s in self.site.presence_strings):
                return DetectionStatus.NOT_FOUND
            return DetectionStatus.FOUND if 200 <= res.status_code < 300 else DetectionStatus.NOT_FOUND

        return DetectionStatus.UNKNOWN
