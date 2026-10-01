# Диспетчер параллельного экспорта отчетов с поддержкой Downloads, TMPDIR и автопросмотра
from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Dict, List, Optional
import uuid
import webbrowser

from epitaph.models.result import ScanSessionResult
from epitaph.reporting.base import BaseReportExporter
from epitaph.reporting.formats.html_export import HtmlReportExporter
from epitaph.reporting.formats.json_export import JsonReportExporter
from epitaph.reporting.formats.pdf_export import PdfReportExporter
from epitaph.reporting.formats.txt_export import TxtReportExporter

logger = logging.getLogger("epitaph.reporting.dispatcher")


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
        Path.home() / "storage" / "shared" / "Downloads",
        Path("/storage/emulated/0/Download"),
        Path("/storage/emulated/0/Downloads"),
        Path("/sdcard/Download"),
        Path("/sdcard/Downloads"),
        Path.home() / "Downloads",
        Path.home() / "downloads",
    ]
    xdg_download = os.environ.get("XDG_DOWNLOAD_DIR")
    if xdg_download:
        candidates.append(Path(xdg_download))

    for candidate in candidates:
        try:
            if is_directory_writable(candidate):
                return candidate
        except OSError:
            continue
    return None


def get_default_report_dir(session_id: str, username: str = "") -> Path:
    folder_name = f"{sanitize_filename(username)}_{session_id}" if username else session_id
    downloads = get_downloads_dir()
    if downloads is not None:
        target = downloads / "Epitaph" / "reports" / folder_name
        try:
            target.mkdir(parents=True, exist_ok=True)
            return target
        except OSError:
            pass

    base_tmp = Path(os.environ.get("TMPDIR") or tempfile.gettempdir())
    target = base_tmp / "epitaph" / "reports" / folder_name
    target.mkdir(parents=True, exist_ok=True)
    return target


def open_in_viewer(target_file: Path) -> bool:
    # Запуск файла во внешнем просмотрщике (Termux / xdg-open / macOS open / браузер)
    resolved = target_file.resolve()
    for cmd in ("termux-open", "xdg-open", "open"):
        opener = shutil.which(cmd)
        if opener:
            try:
                subprocess.Popen([opener, str(resolved)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True
            except Exception:
                pass
    try:
        webbrowser.open(f"file://{resolved}")
        return True
    except Exception:
        pass
    return False


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
            try:
                target_file = target_dir / f"report.{exp.format_name}"
                out = await exp.export(data, target_file)
                try:
                    mode = 0o644 if exp.format_name == "html" else 0o600
                    out.chmod(mode)
                except OSError:
                    pass
                results[exp.format_name] = out
            except Exception as err:
                logger.error("Сбой экспорта в формат %s: %s", exp.format_name, err)

        async with asyncio.TaskGroup() as tg:
            for exp in self.exporters:
                tg.create_task(_run(exp))

        downloads = get_downloads_dir()
        if downloads and "html" in results:
            clean_user = sanitize_filename(data.target.username)
            public_html = downloads / f"report_{clean_user}_{data.session_id}.html"
            try:
                await asyncio.to_thread(shutil.copyfile, results["html"], public_html)
                try:
                    public_html.chmod(0o644)
                except OSError:
                    pass
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
        downloads = get_downloads_dir()

        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            target_file = output_path
        elif downloads is not None:
            target_file = downloads / f"report_{clean_user}_{data.session_id}.html"
        else:
            target_dir = get_default_report_dir(data.session_id, data.target.username)
            target_dir.mkdir(parents=True, exist_ok=True)
            target_file = target_dir / "report.html"

        result_path = await HtmlReportExporter().export(data, target_file)
        try:
            result_path.chmod(0o644)
        except OSError:
            pass

        # Сохранение резервной копии отчета в каталоге сессии
        session_dir = get_default_report_dir(data.session_id, data.target.username)
        if session_dir != result_path.parent:
            try:
                session_dir.mkdir(parents=True, exist_ok=True)
                backup_copy = session_dir / "report.html"
                await asyncio.to_thread(shutil.copyfile, result_path, backup_copy)
                try:
                    backup_copy.chmod(0o600)
                except OSError:
                    pass
            except OSError:
                pass

        # Автоматическое открытие отчета в браузере или системном просмотрщике
        open_in_viewer(result_path)
        return result_path
