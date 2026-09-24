import asyncio
from collections import deque
from typing import Deque, List, Optional
import httpx
from epitaph.models.proxy import ProxyEntity
from epitaph.network.circuit_breaker import CircuitBreaker


class ProxyManager:
    def __init__(
        self,
        proxies: Optional[List[ProxyEntity]] = None,
        circuit_breaker: Optional[CircuitBreaker] = None,
        health_check_url: str = "https://cloudflare.com/cdn-cgi/trace",
    ) -> None:
        self.active_proxies: Deque[ProxyEntity] = deque(proxies or [])
        self.quarantine_proxies: List[ProxyEntity] = []
        self.circuit_breaker = circuit_breaker or CircuitBreaker()
        self.health_check_url = health_check_url
        self._lock = asyncio.Lock()

    async def lease_proxy(self) -> Optional[ProxyEntity]:
        async with self._lock:
            if not self.active_proxies:
                return None
            proxy = self.active_proxies.popleft()
            self.active_proxies.append(proxy)
            return proxy

    async def report_success(self, proxy: ProxyEntity, latency_ms: float) -> None:
        async with self._lock:
            updated = proxy.model_copy(
                update={"failure_count": 0, "latency_ms": latency_ms, "is_active": True}
            )
            self._replace_in_active(proxy, updated)

    async def report_failure(self, proxy: ProxyEntity) -> None:
        async with self._lock:
            new_failures = proxy.failure_count + 1
            updated = proxy.model_copy(update={"failure_count": new_failures})
            if self.circuit_breaker.should_trip(updated):
                cooldown = self.circuit_breaker.calculate_cooldown()
                quarantined = updated.model_copy(
                    update={"is_active": False, "cooldown_until": cooldown}
                )
                self._remove_from_active(proxy)
                self.quarantine_proxies.append(quarantined)
            else:
                self._replace_in_active(proxy, updated)

    def _replace_in_active(self, old: ProxyEntity, new: ProxyEntity) -> None:
        for idx, item in enumerate(self.active_proxies):
            if item.host == old.host and item.port == old.port:
                self.active_proxies[idx] = new
                break

    def _remove_from_active(self, target: ProxyEntity) -> None:
        self.active_proxies = deque(
            p for p in self.active_proxies if not (p.host == target.host and p.port == target.port)
        )

    async def health_check_loop(self) -> None:
        while True:
            await asyncio.sleep(60)
            async with self._lock:
                recovered: List[ProxyEntity] = []
                remaining: List[ProxyEntity] = []
                for p in self.quarantine_proxies:
                    if self.circuit_breaker.is_cooldown_expired(p):
                        if await self._check_node_health(p):
                            recovered.append(
                                p.model_copy(
                                    update={"failure_count": 0, "is_active": True, "cooldown_until": None}
                                )
                            )
                            continue
                    remaining.append(p)

                self.quarantine_proxies = remaining
                self.active_proxies.extend(recovered)

    async def _check_node_health(self, proxy: ProxyEntity) -> bool:
        try:
            async with httpx.AsyncClient(proxy=proxy.url, timeout=5.0) as client:
                res = await client.get(self.health_check_url)
                return res.status_code == 200
        except Exception:
            return False
