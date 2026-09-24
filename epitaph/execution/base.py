from abc import ABC, abstractmethod
from typing import Dict
import httpx
from playwright.async_api import BrowserContext
from epitaph.models.base import ExecutionType
from epitaph.models.result import CheckResult
from epitaph.models.target import TargetProfile


class BasePlatformChecker(ABC):
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
        return 0.5

    @property
    def headers(self) -> Dict[str, str]:
        return {}

    @abstractmethod
    async def check_http(
        self,
        target: TargetProfile,
        client: httpx.AsyncClient,
    ) -> CheckResult:
        raise NotImplementedError("HTTP check is not implemented for this checker.")

    @abstractmethod
    async def check_browser(
        self,
        target: TargetProfile,
        context: BrowserContext,
    ) -> CheckResult:
        raise NotImplementedError("Browser check is not implemented for this checker.")
