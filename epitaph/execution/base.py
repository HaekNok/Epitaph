# Базовый абстрактный контракт для модулей проверки сервисов
from abc import ABC, abstractmethod
from typing import Any, Dict
import httpx
from epitaph.models.base import ExecutionType
from epitaph.models.result import CheckResult
from epitaph.models.target import TargetProfile

try:
    from playwright.async_api import BrowserContext
except (ImportError, RuntimeError):
    BrowserContext = Any  # type: ignore


class BasePlatformChecker(ABC):
    # Абстрактный контракт для реализации модулей проверки платформ

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def execution_type(self) -> ExecutionType:
        pass

    @property
    def rate_limit_delay(self) -> float:
        # Минимальный интервал между сетевыми запросами
        return 0.5

    @property
    def headers(self) -> Dict[str, str]:
        # Пользовательские HTTP-заголовки
        return {}

    @abstractmethod
    async def check_http(
        self,
        target: TargetProfile,
        client: httpx.AsyncClient,
    ) -> CheckResult:
        # Проверка профиля через асинхронный HTTP-клиент
        raise NotImplementedError("HTTP check is not implemented for this checker.")

    @abstractmethod
    async def check_browser(
        self,
        target: TargetProfile,
        context: BrowserContext,
    ) -> CheckResult:
        # Проверка профиля через headless-браузер
        raise NotImplementedError("Browser check is not implemented for this checker.")
