import aiofiles
from pathlib import Path
from epitaph.models.result import ScanSessionResult
from epitaph.reporting.base import BaseReportExporter


class JsonReportExporter(BaseReportExporter):
    @property
    def format_name(self) -> str:
        return "json"

    async def export(self, data: ScanSessionResult, output_path: Path) -> Path:
        content = data.model_dump_json(indent=2)
        async with aiofiles.open(output_path, mode="w", encoding="utf-8") as f:
            await f.write(content)
        return output_path
