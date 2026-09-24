import asyncio
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
from epitaph.models.result import ScanSessionResult
from epitaph.reporting.base import BaseReportExporter


class HtmlReportExporter(BaseReportExporter):
    @property
    def format_name(self) -> str:
        return "html"

    def _render_sync(self, data: ScanSessionResult, output_path: Path) -> Path:
        template_dir = Path(__file__).resolve().parent.parent / "templates"
        env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        template = env.get_template("report.html.j2")
        rendered = template.render(data=data)
        output_path.write_text(rendered, encoding="utf-8")
        return output_path

    async def export(self, data: ScanSessionResult, output_path: Path) -> Path:
        return await asyncio.to_thread(self._render_sync, data, output_path)
