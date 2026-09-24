import asyncio
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input
from epitaph.core.engine import ScanEngine
from epitaph.core.events import CheckResultEvent, LogEvent, ProgressUpdateEvent, ScanCompletedEvent
from epitaph.models.target import TargetProfile
from epitaph.ui.widgets.log_stream import LogStreamWidget
from epitaph.ui.widgets.progress_bar import ScanProgressBar
from epitaph.ui.widgets.result_table import ResultTableWidget


class MainScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="main_container"):
            with Horizontal(id="input_bar"):
                yield Input(placeholder="Введите целевой никнейм для сканирования...", id="target_input")
                yield Button("Старт", id="start_button", variant="primary")
            yield ScanProgressBar(id="progress_bar")
            with Horizontal(id="content_panels"):
                yield ResultTableWidget(id="result_table")
                yield LogStreamWidget(id="log_stream")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start_button":
            self.action_start_scan()

    def action_start_scan(self) -> None:
        target_input = self.query_one("#target_input", Input)
        username = target_input.value.strip()
        if not username:
            log_widget = self.query_one("#log_stream", LogStreamWidget)
            log_widget.write_line("Никнейм не указан.")
            return

        target = TargetProfile(username=username)
        asyncio.create_task(self._execute_scan(target))

    async def _execute_scan(self, target: TargetProfile) -> None:
        engine = ScanEngine()
        table_widget = self.query_one("#result_table", ResultTableWidget)
        progress_widget = self.query_one("#progress_bar", ScanProgressBar)
        log_widget = self.query_one("#log_stream", LogStreamWidget)

        table_widget.clear_results()
        log_widget.write_line(f"Поиск по цели: {target.username}")

        scan_task = asyncio.create_task(engine.run_scan(target))

        while not scan_task.done() or not engine.event_queue.empty():
            try:
                event = await asyncio.wait_for(engine.event_queue.get(), timeout=0.1)
                if isinstance(event, CheckResultEvent):
                    table_widget.add_result(event.result)
                    log_widget.write_line(f"[{event.result.platform_name}] {event.result.status}")
                elif isinstance(event, ProgressUpdateEvent):
                    progress_widget.update_progress(event.completed, event.total)
                elif isinstance(event, LogEvent):
                    log_widget.write_line(f"[{event.level}] {event.message}")
                elif isinstance(event, ScanCompletedEvent):
                    log_widget.write_line("Сканирование завершено. Отчеты сформированы.")
            except asyncio.TimeoutError:
                continue

        await scan_task
