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


def is_android() -> bool:
    return bool(
        os.environ.get("TERMUX_VERSION")
        or "com.termux" in os.environ.get("PREFIX", "")
        or "com.termux" in str(Path.home())
        or os.environ.get("ANDROID_ROOT")
        or Path("/storage/emulated/0").exists()
        or Path("/sdcard").exists()
    )


def is_directory_writable(path: Path) -> bool:
    # Фактическая проверка записи через создание файла в обход системного бага os.access на FUSE
    test_file = None
    try:
        resolved = path.resolve()
        if not resolved.is_dir():
            return False
        test_file = resolved / f".epitaph_{uuid.uuid4().hex[:6]}.tmp"
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


def sanitize_filename(name: str) -> str:
    cleaned = "".join(c for c in name if c.isalnum() or c in ("-", "_")).strip()
    return cleaned or "target"


def get_downloads_dir() -> Optional[Path]:
    candidates: List[Path] = [
        Path.home() / "storage" / "downloads",
        Path.home() / "storage" / "shared" / "Download",
        Path.home() / "storage" / "shared" / "Downloads",
        Path("/storage/emulated/0/Download"),
        Path("/storage/emulated/0/Downloads"),
        Path("/sdcard/Download"),
        Path("/sdcard/Downloads"),
    ]

    xdg_download = os.environ.get("XDG_DOWNLOAD_DIR")
    if xdg_download:
        candidates.append(Path(xdg_download))

    candidates.extend([
        Path.home() / "Downloads",
        Path.home() / "downloads",
    ])

    for candidate in candidates:
        try:
            if is_directory_writable(candidate):
                return candidate.resolve()
        except OSError:
            continue

    if not is_android():
        desktop = Path.home() / "Downloads"
        try:
            desktop.mkdir(parents=True, exist_ok=True)
            if is_directory_writable(desktop):
                return desktop.resolve()
        except OSError:
            pass

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
            results[exp.format_name] = await exp.export(data, target_file)

        async with asyncio.TaskGroup() as tg:
            for exp in self.exporters:
                tg.create_task(_run(exp))

        downloads = get_downloads_dir()
        if downloads and "html" in results:
            clean_user = sanitize_filename(data.target.username)
            direct_html = downloads / f"report_{clean_user}_{data.session_id}.html"
            try:
                await asyncio.to_thread(shutil.copyfile, results["html"], direct_html)
                results["html_direct"] = direct_html
            except OSError:
                pass

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
            downloads = get_downloads_dir()
            if downloads is not None:
                clean_user = sanitize_filename(data.target.username)
                target_file = downloads / f"report_{clean_user}_{data.session_id}.html"
            else:
                target_dir = get_default_report_dir(data.session_id, data.target.username)
                target_dir.mkdir(parents=True, exist_ok=True)
                target_file = target_dir / "report.html"

        result_path = await HtmlReportExporter().export(data, target_file)

        session_dir = get_default_report_dir(data.session_id, data.target.username)
        if session_dir != result_path.parent:
            try:
                session_dir.mkdir(parents=True, exist_ok=True)
                await asyncio.to_thread(shutil.copyfile, result_path, session_dir / "report.html")
            except OSError:
                pass

        return result_path
