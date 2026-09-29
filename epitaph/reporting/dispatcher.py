import asyncio
import os
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from epitaph.models.result import ScanSessionResult
from epitaph.reporting.base import BaseReportExporter
from epitaph.reporting.formats.html_export import HtmlReportExporter
from epitaph.reporting.formats.json_export import JsonReportExporter
from epitaph.reporting.formats.pdf_export import PdfReportExporter
from epitaph.reporting.formats.txt_export import TxtReportExporter


def sanitize_filename(name: str) -> str:
    cleaned = "".join(c for c in name if c.isalnum() or c in ("-", "_")).strip()
    return cleaned or "target"


def get_default_report_dir(session_id: str, username: str = "") -> Path:
    # Защищенный приватный каталог отчетов с правами 0700 для предотвращения утечек в Termux
    folder_name = f"{sanitize_filename(username)}_{session_id}" if username else session_id
    base_dir = Path.home() / ".epitaph" / "reports"
    target = base_dir / folder_name
    target.mkdir(parents=True, exist_ok=True)
    try:
        base_dir.chmod(0o700)
        target.chmod(0o700)
    except OSError:
        pass
    return target


class ReportDispatcher:
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
        target_dir = output_base or get_default_report_dir(data.session_id, data.target.username)
        target_dir.mkdir(parents=True, exist_ok=True)
        results: Dict[str, Path] = {}

        async def _run(exp: BaseReportExporter) -> None:
            target_file = target_dir / f"report.{exp.format_name}"
            out = await exp.export(data, target_file)
            try:
                out.chmod(0o600)
            except OSError:
                pass
            results[exp.format_name] = out

        async with asyncio.TaskGroup() as tg:
            for exp in self.exporters:
                tg.create_task(_run(exp))

        return results

    async def export_html(
        self,
        data: ScanSessionResult,
        output_path: Optional[Path] = None,
    ) -> Path:
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            target_file = output_path
        else:
            target_dir = get_default_report_dir(data.session_id, data.target.username)
            clean_user = sanitize_filename(data.target.username)
            target_file = target_dir / f"report_{clean_user}_{data.session_id}.html"

        result_path = await HtmlReportExporter().export(data, target_file)
        try:
            result_path.chmod(0o600)
        except OSError:
            pass

        return result_path
