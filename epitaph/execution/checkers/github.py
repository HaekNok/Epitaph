# Модуль проверки существования аккаунта GitHub через HTTP API
import time
from typing import Any, Dict
import httpx
from epitaph.execution.base import BasePlatformChecker
from epitaph.execution.registry import register_checker
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.result import CheckResult
from epitaph.models.target import TargetProfile


@register_checker
class GitHubChecker(BasePlatformChecker):
    # Чекер профилей GitHub с HTTP-проверкой без использования браузера

    @property
    def name(self) -> str:
        return "GitHub"

    @property
    def execution_type(self) -> ExecutionType:
        return ExecutionType.HTTP

    @property
    def rate_limit_delay(self) -> float:
        return 0.3

    @property
    def headers(self) -> Dict[str, str]:
        return {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        }

    async def check_browser(
        self, target: TargetProfile, context: Any
    ) -> CheckResult:
        # Возврат статуса ошибки конфигурации вместо проброса исключения
        return CheckResult(
            platform_name=self.name,
            target=target,
            status=DetectionStatus.ERROR,
            execution_type=self.execution_type,
            error_message="GitHub чекер поддерживает только HTTP-выполнение.",
        )

    async def check_http(
        self,
        target: TargetProfile,
        client: httpx.AsyncClient,
    ) -> CheckResult:
        # Проверка доступности профиля по HTTP кодам ответа
        url = f"https://github.com/{target.username}"
        start_time = time.perf_counter()
        try:
            response = await client.get(url, headers=self.headers, follow_redirects=False)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            if response.status_code == 200:
                # Маркер страницы soft-404 при удаленном или скрытом профиле GitHub
                if "Not Found" in response.text and "Find what you need" in response.text:
                    status = DetectionStatus.NOT_FOUND
                    profile_url = None
                else:
                    status = DetectionStatus.FOUND
                    profile_url = url
            elif response.status_code == 404:
                status = DetectionStatus.NOT_FOUND
                profile_url = None
            elif response.status_code == 429:
                status = DetectionStatus.RATE_LIMITED
                profile_url = None
            elif response.status_code in (403, 401):
                status = DetectionStatus.BLOCKED
                profile_url = None
            else:
                status = DetectionStatus.UNKNOWN
                profile_url = None

            return CheckResult(
                platform_name=self.name,
                target=target,
                status=status,
                profile_url=profile_url,
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
                error_message=f"Timeout: {str(exc)}",
            )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return CheckResult(
                platform_name=self.name,
                target=target,
                status=DetectionStatus.ERROR,
                response_time_ms=elapsed_ms,
                execution_type=self.execution_type,
                error_message=f"Unhandled error: {type(exc).__name__} {str(exc)}",
            )
