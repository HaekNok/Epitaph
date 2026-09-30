# Диспетчер параллельного экспорта отчетов с приватным хранилищем и поддержкой Downloads
from __future__ import annotations

import asyncio
import os
from pathlib import Path
import shutil
import tempfile
from typing import Dict, List, Optional
import uuid

from epitaph.models.result import ScanSessionResult
from epitaph.reporting.base import BaseReportExporter
from epitaph.reporting.formats.html_export import HtmlReportExporter
from epitaph.reporting.formats.json_export import JsonReportExporter
from epitaph.reporting.formats.pdf_export import PdfReportExporter
from epitaph.reporting.formats.txt_export import TxtReportExporter


def sanitize_filename(name: str) -> str:
    cleaned = "".join(c for c in name if c.isalnum() or c in ("-", "_")).strip()
    return cleaned or "target"


def is_directory_writable(path: Path) -> bool:
    test_file = None
    try:
        if not path.is_dir():
            return False
        test_file = path / f"epitaph_{uuid.uuid4().hex[:6]}.tmp"
        test_file.touch(exist_ok=True)
        return True
    except OSError:
        return False
    finally:
        if test_file:
            try:
                test_file.unlink(missing_ok=True)
            except OSError:
                pass


def get_downloads_dir() -> Optional[Path]:
    candidates: List[Path] = [
        Path.home() / "storage" / "downloads",
        Path.home() / "storage" / "shared" / "Download",
        Path("/storage/emulated/0/Download"),
        Path("/sdcard/Download"),
        Path.home() / "Downloads",
    ]
    for candidate in candidates:
        try:
            if is_directory_writable(candidate):
                return candidate
        except OSError:
            continue
    return None


def get_default_report_dir(session_id: str, username: str = "") -> Path:
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

        # Дублирование HTML в публичный каталог Downloads
        downloads = get_downloads_dir()
        if downloads and "html" in results:
            clean_user = sanitize_filename(data.target.username)
            public_html = downloads / f"report_{clean_user}_{data.session_id}.html"
            try:
                await asyncio.to_thread(shutil.copyfile, results["html"], public_html)
                results["html_direct"] = public_html
            except OSError:
                pass

        return results

    async def export_html(
        self,
        data: ScanSessionResult,
        output_path: Optional[Path] = None,
    ) -> Path:
        clean_user = sanitize_filename(data.target.username)
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            target_file = output_path
        else:
            target_dir = get_default_report_dir(data.session_id, data.target.username)
            # Внутри уникальной папки сессии сохраняем стандартное и компактное имя report.html
            target_file = target_dir / "report.html"

        result_path = await HtmlReportExporter().export(data, target_file)
        try:
            result_path.chmod(0o600)
        except OSError:
            pass

        downloads = get_downloads_dir()
        target_open = result_path
        if downloads:
            public_file = downloads / f"report_{clean_user}_{data.session_id}.html"
            try:
                await asyncio.to_thread(shutil.copyfile, result_path, public_file)
                target_open = public_file
            except OSError:
                pass

        opener = shutil.which("termux-open") or shutil.which("xdg-open")
        if opener:
            try:
                import subprocess
                subprocess.Popen([opener, str(target_open)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass

        return target_open
