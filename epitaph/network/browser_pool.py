# Менеджер браузерных контекстов с безопасным импортом Playwright
import logging
import os
from typing import Any, Optional
from epitaph.models.proxy import ProxyEntity
from epitaph.utils.user_agents import UserAgentManager

logger = logging.getLogger("epitaph.network.browser_pool")

try:
    from playwright.async_api import Browser, BrowserContext, async_playwright

    HAS_PLAYWRIGHT = True
except (ImportError, RuntimeError):
    Browser = Any  # type: ignore
    BrowserContext = Any  # type: ignore
    HAS_PLAYWRIGHT = False
    logger.warning(
        "Playwright недоступен в текущем окружении (Android Termux). "
        "Браузерный режим отключен, сканирование выполняется в чистом HTTP-режиме."
    )


class PlaywrightBrowserPool:
    # Менеджер единого процесса браузера и изолированных контекстов

    def __init__(
        self,
        user_agent_manager: Optional[UserAgentManager] = None,
        insecure_tls: bool = False,
    ) -> None:
        self.user_agent_manager = user_agent_manager or UserAgentManager()
        self.insecure_tls = insecure_tls
        self._playwright: Optional[Any] = None
        self._browser: Optional[Browser] = None

    async def start(self) -> None:
        # Запуск процесса Chromium с включенной по умолчанию песочницей
        if not HAS_PLAYWRIGHT:
            raise RuntimeError(
                "Браузерный режим недоступен: Playwright не поддерживается в среде Android Termux."
            )
        if not self._browser:
            args = ["--disable-gpu", "--disable-dev-shm-usage"]
            if os.environ.get("EPITAPH_FORCE_NO_SANDBOX", "0").lower() in ("1", "true", "yes"):
                args.append("--no-sandbox")

            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=args,
            )

    async def create_context(
        self,
        proxy: Optional[ProxyEntity] = None,
        insecure_tls: Optional[bool] = None,
    ) -> BrowserContext:
        # Создание контекста с принудительной валидацией TLS по умолчанию
        if not HAS_PLAYWRIGHT:
            raise RuntimeError(
                "Браузерный контекст не может быть создан: Playwright недоступен."
            )
        if not self._browser:
            await self.start()

        if self._browser is None:
            raise RuntimeError("Браузер Playwright не был запущен.")

        proxy_config = {"server": proxy.url} if proxy else None
        ua = self.user_agent_manager.get_random_user_agent()

        allow_insecure = (
            insecure_tls
            if insecure_tls is not None
            else (
                self.insecure_tls
                or os.environ.get("EPITAPH_INSECURE_TLS", "0").lower() in ("1", "true", "yes")
            )
        )

        return await self._browser.new_context(
            proxy=proxy_config,
            user_agent=ua,
            ignore_https_errors=allow_insecure,
        )

    async def close(self) -> None:
        # Корректное освобождение ресурсов браузера и остановка драйвера
        if self._browser:
            await self._browser.close()
            self._browser = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None
