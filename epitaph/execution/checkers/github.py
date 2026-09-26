# Чекер профиля GitHub с соблюдением контракта BasePlatformChecker
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
    # Модуль асинхронной проверки профиля на платформе GitHub

    @property
    def name(self) -> str:
        return "GitHub"

    @property
    def execution_type(self) -> ExecutionType:
        return ExecutionType.HTTP

    @property
    def rate_limit_delay(self) -> float:
        # Задержка между запросами к GitHub
        return 0.3

    @property
    def headers(self) -> Dict[str, str]:
        # Пользовательские HTTP-заголовки с реалистичной маскировкой под браузер
        return {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,ru;q=0.8,uk;q=0.7",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
            ),
            "Sec-Ch-Ua": '"Chromium";v="126", "Not/A)Brand";v="8"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        }

    async def check_browser(self, target: TargetProfile, context: Any) -> CheckResult:
        # Возврат детерминированного результата при неподдерживаемом типе выполнения
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
        # Выполнение асинхронной проверки доступности профиля по HTTP
        url = f"https://github.com/{target.username}"
        start_time = time.perf_counter()
        try:
            response = await client.get(url, headers=self.headers, follow_redirects=True)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            if response.status_code == 200:
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
