# Диспетчер параллельного экспорта отчетов во все поддерживаемые форматы
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
    # Определение работы на платформе Android или Termux
    return bool(
        os.environ.get("TERMUX_VERSION")
        or "com.termux" in os.environ.get("PREFIX", "")
        or "com.termux" in str(Path.home())
        or os.environ.get("ANDROID_ROOT")
        or Path("/storage/emulated/0").exists()
        or Path("/sdcard").exists()
    )


def is_directory_writable(directory: Path) -> bool:
    # Проверка доступности каталога на запись через создание временного файла
    test_file = None
    try:
        if not directory.is_dir():
            return False
        test_file = directory / f"epitaph_write_test_{uuid.uuid4().hex[:6]}.tmp"
        test_file.touch(exist_ok=True)
        return True
    except OSError:
        return False
    finally:
        if test_file is not None:
            try:
                test_file.unlink(missing_ok=True)
            except OSError:
                pass


def sanitize_filename(name: str) -> str:
    # Очистка имени от символов, недопустимых в именах файлов
    cleaned = "".join(c for c in name if c.isalnum() or c in ("-", "_")).strip()
    return cleaned or "target"


def get_downloads_dir() -> Optional[Path]:
    # Поиск доступного каталога загрузок с проверкой фактической доступности на запись
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
                return candidate
        except OSError:
            continue

    if not is_android():
        desktop_downloads = Path.home() / "Downloads"
        try:
            desktop_downloads.mkdir(parents=True, exist_ok=True)
            if is_directory_writable(desktop_downloads):
                return desktop_downloads
        except OSError:
            pass

    return None


def get_default_report_dir(session_id: str, username: str = "") -> Path:
    # Определение каталога отчетов с приоритетом папки загрузок и откатом к TMPDIR
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

        # При наличии каталога Downloads дублируем HTML прямо в Downloads для удобства
        downloads = get_downloads_dir()
        if downloads is not None and "html" in results:
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
        # Экспорт отдельного HTML-отчета напрямую в Downloads с дублированием в архив
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

        html_exporter = HtmlReportExporter()
        result_path = await html_exporter.export(data, target_file)

        # Синхронизация резервной копии отчета в каталоге сессии
        session_dir = get_default_report_dir(data.session_id, data.target.username)
        if session_dir != result_path.parent:
            try:
                session_dir.mkdir(parents=True, exist_ok=True)
                backup_copy = session_dir / "report.html"
                await asyncio.to_thread(shutil.copyfile, result_path, backup_copy)
            except OSError:
                pass

        # Автоматическое открытие отчета в браузере Android через termux-open
        opener = shutil.which("termux-open") or shutil.which("xdg-open")
        if opener:
            try:
                import subprocess
                subprocess.Popen([opener, str(result_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass

        return result_path
