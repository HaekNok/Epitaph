from typing import Optional
from playwright.async_api import Browser, BrowserContext, async_playwright
from epitaph.models.proxy import ProxyEntity
from epitaph.utils.user_agents import UserAgentManager


class PlaywrightBrowserPool:
    def __init__(self, user_agent_manager: Optional[UserAgentManager] = None) -> None:
        self.user_agent_manager = user_agent_manager or UserAgentManager()
        self._playwright = None
        self._browser: Optional[Browser] = None

    async def start(self) -> None:
        if not self._browser:
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
            )

    async def create_context(self, proxy: Optional[ProxyEntity] = None) -> BrowserContext:
        if not self._browser:
            await self.start()

        if self._browser is None:
            raise RuntimeError("Браузер Playwright не был запущен.")

        proxy_config = {"server": proxy.url} if proxy else None
        ua = self.user_agent_manager.get_random_user_agent()

        return await self._browser.new_context(
            proxy=proxy_config,
            user_agent=ua,
            ignore_https_errors=True,
        )

    async def close(self) -> None:
        if self._browser:
            await self._browser.close()
            self._browser = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None
