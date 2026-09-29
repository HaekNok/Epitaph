import asyncio
import random
import time
from typing import Dict
from urllib.parse import urlparse


class DomainRateLimiter:
    def __init__(self) -> None:
        self._last_request_times: Dict[str, float] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        self._global_lock = asyncio.Lock()

    async def _get_domain_lock(self, domain: str) -> asyncio.Lock:
        async with self._global_lock:
            if domain not in self._locks:
                self._locks[domain] = asyncio.Lock()
            return self._locks[domain]

    def extract_domain(self, url: str) -> str:
        parsed = urlparse(url)
        return parsed.netloc.lower() or url.lower()

    def calculate_jittered_delay(self, base_delay: float) -> float:
        if base_delay <= 0.0:
            return 0.0
        # Адаптивный рандомизированный джиттер от -20% до +30% к интервалу
        return base_delay * random.uniform(0.8, 1.3)

    async def acquire(self, domain: str, delay_seconds: float) -> None:
        lock = await self._get_domain_lock(domain)
        async with lock:
            effective_delay = self.calculate_jittered_delay(delay_seconds)
            now = time.monotonic()
            elapsed = now - self._last_request_times.get(domain, 0.0)
            if elapsed < effective_delay:
                await asyncio.sleep(effective_delay - elapsed)
            self._last_request_times[domain] = time.monotonic()
