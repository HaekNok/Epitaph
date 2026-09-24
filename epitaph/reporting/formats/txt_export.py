import aiofiles
from pathlib import Path
from epitaph.models.result import ScanSessionResult
from epitaph.reporting.base import BaseReportExporter


class TxtReportExporter(BaseReportExporter):
    @property
    def format_name(self) -> str:
        return "txt"

    async def export(self, data: ScanSessionResult, output_path: Path) -> Path:
        lines = [
            "=" * 72,
            f"ОТЧЕТ СКАНИРОВАНИЯ EPITAPH: {data.target.username}",
            f"Идентификатор сессии: {data.session_id}",
            f"Начало: {data.start_time.isoformat()}",
            f"Завершение: {data.end_time.isoformat()}",
            f"Всего проверено: {data.total_scanned} | Найдено: {data.found_count}",
            "=" * 72,
            f"{'Платформа':<20} | {'Статус':<15} | {'Задержка':<10} | Ссылка",
            "-" * 72,
        ]

        for res in data.results:
            url_str = res.profile_url or "-"
            lines.append(
                f"{res.platform_name:<20} | {str(res.status):<15} | {res.response_time_ms:>6.1f} ms | {url_str}"
            )

        lines.append("=" * 72)
        content = "\n".join(lines) + "\n"

        async with aiofiles.open(output_path, mode="w", encoding="utf-8") as f:
            await f.write(content)
        return output_path
