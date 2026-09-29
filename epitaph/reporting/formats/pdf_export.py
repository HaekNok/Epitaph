import asyncio
import html
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from epitaph.models.result import ScanSessionResult
from epitaph.reporting.base import BaseReportExporter


class PdfReportExporter(BaseReportExporter):
    @property
    def format_name(self) -> str:
        return "pdf"

    def _render_sync_pdf(self, data: ScanSessionResult, output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        doc = SimpleDocTemplate(str(output_path), pagesize=letter)
        styles = getSampleStyleSheet()

        safe_username = html.escape(data.target.username)
        safe_session_id = html.escape(data.session_id)
        elements = [
            Paragraph(f"Epitaph Scan Report: {safe_username}", styles["Heading1"]),
            Spacer(1, 12),
            Paragraph(
                f"Session ID: {safe_session_id}<br/>"
                f"Start: {html.escape(data.start_time.isoformat())}<br/>"
                f"End: {html.escape(data.end_time.isoformat())}<br/>"
                f"Total Scanned: {data.total_scanned} | Found: {data.found_count}",
                styles["Normal"],
            ),
            Spacer(1, 16),
        ]

        table_data = [["Platform", "Status", "Latency (ms)", "URL"]]
        for res in data.results:
            safe_platform = html.escape(res.platform_name)
            safe_status = html.escape(str(res.status))
            safe_url = html.escape(res.profile_url or "-")
            table_data.append([
                safe_platform,
                safe_status,
                f"{res.response_time_ms:.1f}",
                safe_url,
            ])

        pdf_table = Table(table_data, colWidths=[100, 90, 80, 230])
        pdf_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkslategray),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ]))
        elements.append(pdf_table)

        doc.build(elements)
        try:
            output_path.chmod(0o600)
        except OSError:
            pass
        return output_path

    async def export(self, data: ScanSessionResult, output_path: Path) -> Path:
        # Тяжелая сборка PDF делегируется в пул потоков для сохранения отзывчивости Textual
        return await asyncio.to_thread(self._render_sync_pdf, data, output_path)
