# Диспетчер параллельного экспорта отчетов во все поддерживаемые форматы
import asyncio
import os
import tempfile
from pathlib import Path
from typing import Dict, List, Optional
from epitaph.models.result import ScanSessionResult
from epitaph.reporting.base import BaseReportExporter
from epitaph.reporting.formats.html_export import HtmlReportExporter
from epitaph.reporting.formats.json_export import JsonReportExporter
from epitaph.reporting.formats.pdf_export import PdfReportExporter
from epitaph.reporting.formats.txt_export import TxtReportExporter


def get_default_report_dir(session_id: str, username: str = "") -> Path:
    # Определение кроссплатформенного каталога отчетов с поддержкой Termux TMPDIR
    base_tmp = Path(os.environ.get("TMPDIR") or tempfile.gettempdir())
    folder_name = f"{username}_{session_id}" if username else session_id
    return base_tmp / "epitaph" / "reports" / folder_name


class ReportDispatcher:
    # Диспетчер параллельного экспорта отчетов с безопасными путями

    def __init__(self, exporters: Optional[List[BaseReportExporter]] = None) -> None:
        self.exporters = exporters or [
            JsonReportExporter(),
            TxtReportExporter(),
            HtmlReportExporter(),
            PdfReportExporter(),
        ]

    async def export_all(
        self,
        data: ScanSessionResult,
        output_base: Optional[Path] = None,
    ) -> Dict[str, Path]:
        # Параллельная выгрузка всех форматов с гарантией создания директории
        target_dir = output_base or get_default_report_dir(data.session_id, data.target.username)
        target_dir.mkdir(parents=True, exist_ok=True)
        results: Dict[str, Path] = {}

        async def _run_export(exporter: BaseReportExporter) -> None:
            target_file = target_dir / f"report.{exporter.format_name}"
            out = await exporter.export(data, target_file)
            results[exporter.format_name] = out

        # Запуск экспорта в изолированной группе асинхронных задач
        async with asyncio.TaskGroup() as tg:
            for exp in self.exporters:
                tg.create_task(_run_export(exp))

        return results

    async def export_html(
        self,
        data: ScanSessionResult,
        output_path: Optional[Path] = None,
    ) -> Path:
        # Экспорт отдельного HTML-отчета с изоляцией рендеринга в пуле потоков
        if output_path is None:
            target_dir = get_default_report_dir(data.session_id, data.target.username)
            target_dir.mkdir(parents=True, exist_ok=True)
            target_file = target_dir / "report.html"
        else:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            target_file = output_path

        html_exporter = HtmlReportExporter()
        return await html_exporter.export(data, target_file)
