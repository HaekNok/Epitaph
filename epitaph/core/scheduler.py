import asyncio
from typing import Optional

from epitaph.core.limiter import DomainRateLimiter
from epitaph.execution.base import BasePlatformChecker
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.result import CheckResult
from epitaph.models.target import TargetProfile
from epitaph.network.browser_pool import PlaywrightBrowserPool
from epitaph.network.http_client import HttpClientManager
from epitaph.network.proxy_manager import ProxyManager


class TaskScheduler:
    def __init__(
        self,
        max_concurrent_workers: int = 50,
        rate_limiter: Optional[DomainRateLimiter] = None,
        proxy_manager: Optional[ProxyManager] = None,
        http_client: Optional[HttpClientManager] = None,
        browser_pool: Optional[PlaywrightBrowserPool] = None,
    ) -> None:
        self.semaphore = asyncio.Semaphore(max_concurrent_workers)
        self.rate_limiter = rate_limiter or DomainRateLimiter()
        self.proxy_manager = proxy_manager
        self.http_client = http_client or HttpClientManager()
        self._browser_pool = browser_pool

    @property
    def browser_pool(self) -> PlaywrightBrowserPool:
        if self._browser_pool is None:
            self._browser_pool = PlaywrightBrowserPool()
        return self._browser_pool

    async def run_checker(
        self,
        checker: BasePlatformChecker,
        target: TargetProfile,
        result_queue: Optional[asyncio.Queue[CheckResult]] = None,
    ) -> CheckResult:
        async with self.semaphore:
            proxy = await self.proxy_manager.lease_proxy() if self.proxy_manager else None
            raw_domain = getattr(checker, "domain", None)
            domain = self.rate_limiter.extract_domain(raw_domain or checker.name)
            await self.rate_limiter.acquire(domain, checker.rate_limit_delay)

            try:
                if checker.execution_type == ExecutionType.HTTP:
                    client = await self.http_client.get_client(proxy)
                    result = await checker.check_http(target, client)
                else:
                    context = await self.browser_pool.create_context(proxy)
                    try:
                        result = await checker.check_browser(target, context)
                    finally:
                        await context.close()

                if self.proxy_manager and proxy:
                    await self.proxy_manager.report_success(proxy, result.response_time_ms)

            except Exception as err:
                if self.proxy_manager and proxy:
                    await self.proxy_manager.report_failure(proxy)
                result = CheckResult(
                    platform_name=checker.name,
                    target=target,
                    status=DetectionStatus.ERROR,
                    response_time_ms=0.0,
                    execution_type=checker.execution_type,
                    error_message=str(err),
                )

            if result_queue is not None:
                await result_queue.put(result)
            return result
