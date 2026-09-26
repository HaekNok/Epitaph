# Чекер профиля Steam с поддержкой чистого HTTP-выполнения и браузерного режима
import time
from typing import Any, Dict
import httpx
from epitaph.execution.base import BasePlatformChecker
from epitaph.execution.registry import register_checker
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.result import CheckResult
from epitaph.models.target import TargetProfile

try:
    from playwright.async_api import BrowserContext, TimeoutError as PlaywrightTimeoutError
    HAS_PLAYWRIGHT = True
except (ImportError, RuntimeError):
    BrowserContext = Any  # type: ignore
    PlaywrightTimeoutError = TimeoutError  # type: ignore
    HAS_PLAYWRIGHT = False


@register_checker
class SteamChecker(BasePlatformChecker):
    # Модуль проверки существования аккаунта Steam Community с приоритетом HTTP

    @property
    def name(self) -> str:
        return "Steam"

    @property
    def execution_type(self) -> ExecutionType:
        # Автономное выполнение через легкий HTTP-клиент без Playwright
        return ExecutionType.HTTP

    @property
    def rate_limit_delay(self) -> float:
        # Задержка между запросами к Steam Community
        return 1.0

    @property
    def headers(self) -> Dict[str, str]:
        # Пользовательские HTTP-заголовки
        return {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,ru;q=0.8,uk;q=0.7",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
            ),
        }

    async def check_http(
        self,
        target: TargetProfile,
        client: httpx.AsyncClient,
    ) -> CheckResult:
        # Быстрая асинхронная проверка профиля Steam через HTTP GET запрос
        url = f"https://steamcommunity.com/id/{target.username}"
        start_time = time.perf_counter()
        try:
            response = await client.get(url, headers=self.headers, follow_redirects=True)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            if response.status_code == 404:
                status = DetectionStatus.NOT_FOUND
                profile_url = None
            elif response.status_code == 200:
                body = response.text
                if "The specified profile could not be found" in body or "error_ctn" in body:
                    status = DetectionStatus.NOT_FOUND
                    profile_url = None
                elif "actual_persona_name" in body or "persona_name" in body or "Steam Community ::" in body:
                    status = DetectionStatus.FOUND
                    profile_url = url
                else:
                    status = DetectionStatus.NOT_FOUND
                    profile_url = None
            elif response.status_code == 429:
                status = DetectionStatus.RATE_LIMITED
                profile_url = None
            elif response.status_code in (401, 403):
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

    async def check_browser(
        self,
        target: TargetProfile,
        context: BrowserContext,
    ) -> CheckResult:
        # Опциональная браузерная проверка профиля при наличии Playwright
        if not HAS_PLAYWRIGHT or context is None:
            return CheckResult(
                platform_name=self.name,
                target=target,
                status=DetectionStatus.BLOCKED,
                execution_type=self.execution_type,
                error_message="Playwright недоступен в текущем окружении.",
            )

        url = f"https://steamcommunity.com/id/{target.username}"
        start_time = time.perf_counter()
        page = None
        try:
            page = await context.new_page()
            response = await page.goto(url, wait_until="domcontentloaded", timeout=7000)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            http_status = response.status if response else None

            error_msg_locator = page.locator("#message .error_ctn")
            if await error_msg_locator.is_visible():
                status = DetectionStatus.NOT_FOUND
                profile_url = None
            else:
                persona_locator = page.locator(".persona_name .actual_persona_name")
                if await persona_locator.is_visible():
                    status = DetectionStatus.FOUND
                    profile_url = url
                else:
                    status = DetectionStatus.NOT_FOUND
                    profile_url = None

            return CheckResult(
                platform_name=self.name,
                target=target,
                status=status,
                profile_url=profile_url,
                response_time_ms=elapsed_ms,
                execution_type=self.execution_type,
                http_status_code=http_status,
            )
        except PlaywrightTimeoutError as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return CheckResult(
                platform_name=self.name,
                target=target,
                status=DetectionStatus.ERROR,
                response_time_ms=elapsed_ms,
                execution_type=self.execution_type,
                error_message=f"Playwright timeout: {exc}",
            )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return CheckResult(
                platform_name=self.name,
                target=target,
                status=DetectionStatus.ERROR,
                response_time_ms=elapsed_ms,
                execution_type=self.execution_type,
                error_message=f"Browser error: {type(exc).__name__} {exc}",
            )
        finally:
            if page:
                await page.close()
