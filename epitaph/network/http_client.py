from typing import Dict, Optional
import httpx
from epitaph.models.proxy import ProxyEntity


class HttpClientManager:
    def __init__(self) -> None:
        self._clients: Dict[str, httpx.AsyncClient] = {}
        self.limits = httpx.Limits(
            max_keepalive_connections=20,
            max_connections=50,
            keepalive_expiry=30.0,
        )
        self.timeout = httpx.Timeout(
            connect=5.0,
            read=10.0,
            write=5.0,
            pool=5.0,
        )

    async def get_client(self, proxy: Optional[ProxyEntity] = None) -> httpx.AsyncClient:
        key = proxy.url if proxy else "direct"
        if key not in self._clients or self._clients[key].is_closed:
            self._clients[key] = httpx.AsyncClient(
                proxy=proxy.url if proxy else None,
                limits=self.limits,
                timeout=self.timeout,
                http2=True,
            )
        return self._clients[key]

    async def close_all(self) -> None:
        for client in self._clients.values():
            if not client.is_closed:
                await client.aclose()
        self._clients.clear()
