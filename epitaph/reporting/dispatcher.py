import asyncio
from pathlib import Path
from typing import Dict, List, Optional
from epitaph.models.result import ScanSessionResult
from epitaph.reporting.base import BaseReportExporter
from epitaph.reporting.formats.html_export import HtmlReportExporter
from epitaph.reporting.formats.json_export import JsonReportExporter
from epitaph.reporting.formats.pdf_export import PdfReportExporter
from epitaph.reporting.formats.txt_export import TxtReportExporter


class ReportDispatcher:
    def __init__(self, exporters: Optional[List[BaseReportExporter]] = None) -> None:
        self.exporters = exporters or [
            JsonReportExporter(),
            TxtReportExporter(),
            HtmlReportExporter(),
            PdfReportExporter(),
        ]

    async def export_all(self, data: ScanSessionResult, output_base: Path) -> Dict[str, Path]:
        output_base.mkdir(parents=True, exist_ok=True)
        results: Dict[str, Path] = {}

        async def _run_export(exporter: BaseReportExporter) -> None:
            target_file = output_base / f"report.{exporter.format_name}"
            out = await exporter.export(data, target_file)
            results[exporter.format_name] = out

        async with asyncio.TaskGroup() as tg:
            for exp in self.exporters:
                tg.create_task(_run_export(exp))

        return results
