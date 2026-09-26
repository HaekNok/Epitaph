# Чекер профиля Steam с безопасным импортом Playwright и контрактом BasePlatformChecker
import time
from typing import Any, Dict
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
    # Модуль проверки существования аккаунта Steam Community

    @property
    def name(self) -> str:
        return "Steam"

    @property
    def execution_type(self) -> ExecutionType:
        return ExecutionType.BROWSER

    @property
    def rate_limit_delay(self) -> float:
        # Задержка между запросами к Steam Community
        return 1.0

    async def check_http(
        self,
        target: TargetProfile,
        client: Any,
    ) -> CheckResult:
        # Возврат детерминированного результата при вызове HTTP вместо выброса исключения
        return CheckResult(
            platform_name=self.name,
            target=target,
            status=DetectionStatus.BLOCKED,
            execution_type=self.execution_type,
            error_message="Steam Community требует браузерного рендеринга для верификации.",
        )

    async def check_browser(
        self,
        target: TargetProfile,
        context: BrowserContext,
    ) -> CheckResult:
        # Проверка профиля через браузерный контекст с валидацией среды
        if not HAS_PLAYWRIGHT:
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
                extracted: Dict[str, Any] = {}
            else:
                persona_locator = page.locator(".persona_name .actual_persona_name")
                if await persona_locator.is_visible():
                    status = DetectionStatus.FOUND
                    profile_url = url
                    display_name = await persona_locator.inner_text()
                    extracted = {"display_name": display_name.strip()}
                else:
                    status = DetectionStatus.NOT_FOUND
                    profile_url = None
                    extracted = {}

            return CheckResult(
                platform_name=self.name,
                target=target,
                status=status,
                profile_url=profile_url,
                response_time_ms=elapsed_ms,
                execution_type=self.execution_type,
                http_status_code=http_status,
                extracted_data=extracted,
            )
        except PlaywrightTimeoutError as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return CheckResult(
                platform_name=self.name,
                target=target,
                status=DetectionStatus.ERROR,
                response_time_ms=elapsed_ms,
                execution_type=self.execution_type,
                error_message=f"Playwright navigation timeout: {str(exc)}",
            )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return CheckResult(
                platform_name=self.name,
                target=target,
                status=DetectionStatus.ERROR,
                response_time_ms=elapsed_ms,
                execution_type=self.execution_type,
                error_message=f"Browser execution failed: {type(exc).__name__} {str(exc)}",
            )
        finally:
            if page:
                await page.close()
