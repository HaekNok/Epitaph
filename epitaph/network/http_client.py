# Менеджер пула асинхронных HTTP-клиентов с адаптивными таймаутами
from typing import Dict, Optional
import httpx
from epitaph.models.proxy import ProxyEntity

try:
    import h2
    HAS_H2 = True
except ImportError:
    HAS_H2 = False


class HttpClientManager:
    # Менеджер постоянных сессий httpx с поддержкой пулов и безопасного протокола

    def __init__(self) -> None:
        self._clients: Dict[str, httpx.AsyncClient] = {}
        self.limits = httpx.Limits(
            max_keepalive_connections=20,
            max_connections=50,
            keepalive_expiry=30.0,
        )
        self.timeout = httpx.Timeout(
            connect=10.0,
            read=15.0,
            write=10.0,
            pool=10.0,
        )

    async def get_client(self, proxy: Optional[ProxyEntity] = None) -> httpx.AsyncClient:
        # Получение клиента для конкретного прокси или прямого сетевого подключения
        key = proxy.url if proxy else "direct"
        if key not in self._clients or self._clients[key].is_closed:
            default_headers = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
                ),
                "Accept-Language": "en-US,en;q=0.9,ru;q=0.8,uk;q=0.7",
            }
            self._clients[key] = httpx.AsyncClient(
                proxy=proxy.url if proxy else None,
                limits=self.limits,
                timeout=self.timeout,
                http2=HAS_H2,
                trust_env=True,
                headers=default_headers,
            )
        return self._clients[key]

    async def close_all(self) -> None:
        # Корректное закрытие всех активных пулов соединений
        for client in self._clients.values():
            if not client.is_closed:
                await client.aclose()
        self._clients.clear()
