from abc import ABC, abstractmethod
from pathlib import Path
from epitaph.models.result import ScanSessionResult


class BaseReportExporter(ABC):
    @property
    @abstractmethod
    def format_name(self) -> str:
        pass

    @abstractmethod
    async def export(self, data: ScanSessionResult, output_path: Path) -> Path:
        pass
