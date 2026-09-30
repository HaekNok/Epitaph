# Экран главного меню TUI-интерфейса Epitaph с поддержкой Maigret
import asyncio
from pathlib import Path
import sys
from typing import Any, Optional
from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.events import Resize
from textual.screen import Screen
from textual.widgets import Button, Input, Static

from epitaph.core.events import (
    CheckResultEvent,
    LogEvent,
    ProgressUpdateEvent,
    ScanCompletedEvent,
)
from epitaph.execution.checkers.google.executor import GoogleExecutor
from epitaph.execution.maigret import MaigretExecutor
from epitaph.models.result import ScanSessionResult
from epitaph.models.target import TargetProfile
from epitaph.ui.widgets.banner import HeaderBanner
from epitaph.ui.widgets.menu_slot import MenuSlot


class MainScreen(Screen[None]):
    BINDINGS = [
        ("s", "save_html", "Сохранить HTML"),
        ("o", "save_html", "Открыть HTML"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.event_queue: asyncio.Queue[Any] = asyncio.Queue()
        self.maigret_executor = MaigretExecutor(event_queue=self.event_queue)
        self.engine = self.maigret_executor.engine
        self.google_executor = GoogleExecutor(
            event_queue=self.event_queue,
            engine=self.engine,
            dispatcher=self.engine.dispatcher,
        )
        self._is_scanning: bool = False
        self._selected_slot: Optional[int] = None
        self._last_session_result: Optional[ScanSessionResult] = None

    def compose(self) -> ComposeResult:
        with Vertical(id="main_container"):
            yield HeaderBanner(id="header_banner")

            menu_frame = Vertical(id="menu_frame")
            menu_frame.border_title = "ДОСТУПНЫЕ МОДУЛИ"
            with menu_frame:
                with Horizontal(id="grid_container"):
                    for col in range(3):
                        with Vertical(classes="menu_column"):
                            start = col * 10 + 1
                            for slot in range(start, start + 10):
                                slot_title = "Nickname" if slot == 1 else ("eMail" if slot == 2 else None)
                                yield MenuSlot(slot_number=slot, title=slot_title)

            with Vertical(id="footer_panel"):
                with Horizontal(id="action_bar"):
                    yield Button("> клавиатура", id="keyboard_button")
                    yield Static(id="action_spacer_left")
                    yield Button("> сохранить HTML", id="save_html_button")
                    yield Static(id="action_spacer_right")
                    yield Button("> выход", id="exit_button")
                yield Static(
                    "[ ожидание ] Выберите слот касанием или введите номер модуля",
                    id="status_message",
                )
                with Horizontal(id="command_bar"):
                    yield Static("Command / Slot > ", id="prompt_label")
                    yield Input(
                        placeholder="введите номер (1-30) или никнейм/email цели...",
                        id="command_input",
                    )

    def on_mount(self) -> None:
        self._apply_responsive_layout(self.size.width)
        self.query_one("#save_html_button", Button).display = False

    def on_resize(self, event: Resize) -> None:
        self._apply_responsive_layout(event.size.width)

    def _apply_responsive_layout(self, width: int) -> None:
        is_compact = width < 80
        try:
            self.query_one("#main_container").set_class(is_compact, "compact-layout")
            self.query_one("#header_banner", HeaderBanner).update_banner(width)
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "keyboard_button":
            self.action_request_keyboard()
        elif event.button.id == "save_html_button":
            asyncio.create_task(self.action_save_html())
        elif event.button.id == "exit_button":
            self.app.exit()

    def action_request_keyboard(self) -> None:
        cmd_input = self.query_one("#command_input", Input)
        cmd_input.focus()
        cmd_input.cursor_position = len(cmd_input.value)

        driver = getattr(self.app, "_driver", None)
        seq = "\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l"
        if driver and hasattr(driver, "write"):
            driver.write(seq)
        else:
            try:
                sys.stdout.write(seq)
                sys.stdout.flush()
            except Exception:
                pass

        self.query_one("#status_message", Static).update(
            "[ клавиатура ] Коснитесь экрана для IME или нажмите VolUp+K"
        )
        self.set_timer(3.0, self._restore_mouse_tracking)

    def _restore_mouse_tracking(self) -> None:
        driver = getattr(self.app, "_driver", None)
        seq = "\x1b[?1000h\x1b[?1002h\x1b[?1006h"
        if driver and hasattr(driver, "write"):
            driver.write(seq)
        else:
            try:
                sys.stdout.write(seq)
                sys.stdout.flush()
            except Exception:
                pass

    @on(Input.Changed, "#command_input")
    def handle_input_changed(self) -> None:
        self._restore_mouse_tracking()

    def _select_slot(self, slot: int) -> None:
        cmd_input = self.query_one("#command_input", Input)
        prompt = self.query_one("#prompt_label", Static)
        status = self.query_one("#status_message", Static)

        if slot == 1:
            self._selected_slot = 1
            prompt.update("Target Nickname > ")
            status.update("[ выбор ] Модуль 1 > Nickname активен. Введите никнейм цели...")
            cmd_input.placeholder = "введите целевой никнейм или 'q' для выхода..."
        elif slot == 2:
            self._selected_slot = 2
            prompt.update("Target eMail > ")
            status.update("[ выбор ] Модуль 2 > eMail активен. Введите email цели...")
            cmd_input.placeholder = "введите email (например, target@gmail.com)..."
        else:
            self._selected_slot = None
            prompt.update("Command / Slot > ")
            status.update(f"[ заглушка ] Слот {slot} > SOON (модуль в разработке)")
            cmd_input.placeholder = "введите номер слота (1-30) или 'q' для выхода..."

        cmd_input.focus()

    @on(MenuSlot.Selected)
    def handle_slot_selected(self, message: MenuSlot.Selected) -> None:
        self._select_slot(message.slot_number)

    @on(Input.Submitted, "#command_input")
    def handle_command_submitted(self, event: Input.Submitted) -> None:
        raw = event.value.strip()
        event.input.value = ""

        if raw.lower() in ("q", "quit", "exit", "выход"):
            self.app.exit()
            return

        if not raw:
            return

        if raw.isdigit() and 1 <= int(raw) <= 30:
            self._select_slot(int(raw))
            return

        # Проверка текстовых команд сохранения и открытия отчета
        if raw.lower() in ("html", "save", "open", "отчет", "сохранить"):
            if self._last_session_result is not None:
                asyncio.create_task(self.action_save_html())
            else:
                status = self.query_one("#status_message", Static)
                status.update("[ ошибка ] Нет данных предыдущего сканирования")
            return

        status = self.query_one("#status_message", Static)
        if self._is_scanning:
            status.update("[ ошибка ] Сканирование уже выполняется...")
            return

        status.update("[ ожидание ] Запрос обрабатывается")
        target = TargetProfile(username=raw)
        is_email = (self._selected_slot == 2) or ("@" in raw)
        asyncio.create_task(self._execute_scan(target, is_email=is_email))

    async def _execute_scan(self, target: TargetProfile, is_email: bool = False) -> None:
        self._is_scanning = True
        status = self.query_one("#status_message", Static)
        save_btn = self.query_one("#save_html_button", Button)
        save_btn.display = False

        executor = self.google_executor if is_email else self.maigret_executor
        scan_task = asyncio.create_task(executor.run_search(target))

        while not scan_task.done() or not self.event_queue.empty():
            try:
                event = await asyncio.wait_for(self.event_queue.get(), timeout=0.1)
                if isinstance(event, CheckResultEvent):
                    status.update(f"[ {event.result.platform_name} ] {event.result.status.value}")
                elif isinstance(event, ProgressUpdateEvent):
                    status.update(f"[ прогресс ] Завершено: {event.completed} из {event.total}")
                elif isinstance(event, LogEvent):
                    status.update(f"[ лог ] {event.message}")
                elif isinstance(event, ScanCompletedEvent):
                    status.update(f"[ готово ] Сессия {event.session_id}: сформировано {len(event.report_paths)} формата отчетов")
                    save_btn.display = True
            except asyncio.TimeoutError:
                continue
            except Exception:
                break

        try:
            self._last_session_result = await scan_task
            found = self._last_session_result.found_count
            status.update(f"[ готово ] Сессия {self._last_session_result.session_id} | Найдено: {found} | 4 формата отчетов")
            save_btn.display = True
        except Exception as err:
            status.update(f"[ сбой ] Ошибка сканирования: {err}")
        finally:
            self._is_scanning = False

    async def action_save_html(self) -> None:
        status = self.query_one("#status_message", Static)
        if self._last_session_result is None:
            status.update("[ ошибка ] Нет данных предыдущего сканирования")
            return

        status.update("[ ожидание ] Экспорт HTML-отчета...")
        try:
            report_path = await self.engine.dispatcher.export_html(self._last_session_result)
            short_path = str(report_path).replace(str(Path.home()), "~")
            status.update(f"[ открыт ] {short_path}")
        except Exception as err:
            status.update(f"[ сбой ] Ошибка создания HTML: {err}")
