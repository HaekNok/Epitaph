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
from epitaph.execution.nickname import NicknameExecutor
from epitaph.execution.checkers.bank_card import BankCardExecutor
from epitaph.execution.checkers.cookies import CookieExecutor
from epitaph.execution.checkers.email.executor import EmailReconExecutor
from epitaph.execution.checkers.fullname import FullNameExecutor
from epitaph.execution.checkers.inn import InnExecutor
from epitaph.execution.checkers.ip import IpExecutor
from epitaph.execution.checkers.mac import MacExecutor
from epitaph.execution.checkers.organization import OrganizationExecutor
from epitaph.execution.checkers.password import PasswordExecutor
from epitaph.execution.checkers.phone import PhoneExecutor
from epitaph.execution.checkers.port_scanner import PortScannerExecutor
from epitaph.execution.checkers.snils import SnilsExecutor
from epitaph.execution.checkers.subdomain import SubdomainExecutor
from epitaph.execution.checkers.telegram import TelegramExecutor
from epitaph.execution.checkers.vehicle import VehicleExecutor

from epitaph.models.result import ScanSessionResult
from epitaph.models.target import TargetProfile
from epitaph.ui.widgets.banner import HeaderBanner
from epitaph.ui.widgets.menu_slot import MenuSlot

SLOT_TITLES: dict[int, str] = {
    1: "Nickname",
    2: "Telegram ID",
    3: "Email Address",
    4: "Phone Number",
    5: "Full Name",
    6: "INN",
    7: "SNILS",
    8: "Car Number",
    9: "Organization",
    10: "Bank Card",
    11: "Password",
    12: "Cookies",
    13: "IP Address",
    14: "Subdomain",
    15: "Port Scanner",
    16: "MAC Address",
}

SLOT_CONFIGS: dict[int, dict[str, str]] = {
    1: {"prompt": "Target Nickname > ", "placeholder": "введите никнейм цели или 'q' для выхода...", "title": "Nickname"},
    2: {"prompt": "Target Telegram > ", "placeholder": "введите username (@target) или t.me/target...", "title": "Telegram ID"},
    3: {"prompt": "Target Email > ", "placeholder": "введите email (например, target@gmail.com)...", "title": "Email Address"},
    4: {"prompt": "Target Phone > ", "placeholder": "введите номер телефона (+380... / +7...)...", "title": "Phone Number"},
    5: {"prompt": "Target Full Name > ", "placeholder": "введите Фамилию Имя Отчество...", "title": "Full Name"},
    6: {"prompt": "Target INN > ", "placeholder": "введите ИНН (10 или 12 цифр)...", "title": "INN"},
    7: {"prompt": "Target SNILS > ", "placeholder": "введите СНИЛС (11 цифр)...", "title": "SNILS"},
    8: {"prompt": "Target Car / VIN > ", "placeholder": "введите госномер или 17-значный VIN...", "title": "Car Number"},
    9: {"prompt": "Target Organization > ", "placeholder": "введите ОГРН или наименование...", "title": "Organization"},
    10: {"prompt": "Target Bank Card > ", "placeholder": "введите номер карты или BIN...", "title": "Bank Card"},
    11: {"prompt": "Target Password > ", "placeholder": "введите пароль для k-Anonymity проверки...", "title": "Password"},
    12: {"prompt": "Target Cookies > ", "placeholder": "вставьте строку куки (Netscape/JSON)...", "title": "Cookies"},
    13: {"prompt": "Target IP > ", "placeholder": "введите IPv4 или IPv6 адрес...", "title": "IP Address"},
    14: {"prompt": "Target Subdomain > ", "placeholder": "введите домен (example.com)...", "title": "Subdomain"},
    15: {"prompt": "Target Port Host > ", "placeholder": "введите хост для проверки TCP-портов...", "title": "Port Scanner"},
    16: {"prompt": "Target MAC > ", "placeholder": "введите MAC-адрес (XX:XX:XX:XX:XX:XX)...", "title": "MAC Address"},
}


class MainScreen(Screen[None]):
    BINDINGS = [
        ("s", "save_html", "Сохранить HTML"),
        ("o", "save_html", "Открыть HTML"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.event_queue: asyncio.Queue[Any] = asyncio.Queue()
        self.nickname_executor = NicknameExecutor(event_queue=self.event_queue)
        self.engine = self.nickname_executor.engine
        self.dispatcher = self.engine.dispatcher

        # Реестр всех 16 специализированных исполнителей функциональной матрицы
        self._executors: dict[int, Any] = {
            1: self.nickname_executor,
            2: TelegramExecutor(event_queue=self.event_queue, engine=self.engine, dispatcher=self.dispatcher),
            3: EmailReconExecutor(event_queue=self.event_queue, engine=self.engine, dispatcher=self.dispatcher),
            4: PhoneExecutor(event_queue=self.event_queue, engine=self.engine, dispatcher=self.dispatcher),
            5: FullNameExecutor(event_queue=self.event_queue, engine=self.engine, dispatcher=self.dispatcher),
            6: InnExecutor(event_queue=self.event_queue, engine=self.engine, dispatcher=self.dispatcher),
            7: SnilsExecutor(event_queue=self.event_queue, engine=self.engine, dispatcher=self.dispatcher),
            8: VehicleExecutor(event_queue=self.event_queue, engine=self.engine, dispatcher=self.dispatcher),
            9: OrganizationExecutor(event_queue=self.event_queue, engine=self.engine, dispatcher=self.dispatcher),
            10: BankCardExecutor(event_queue=self.event_queue, engine=self.engine, dispatcher=self.dispatcher),
            11: PasswordExecutor(event_queue=self.event_queue, engine=self.engine, dispatcher=self.dispatcher),
            12: CookieExecutor(event_queue=self.event_queue, engine=self.engine, dispatcher=self.dispatcher),
            13: IpExecutor(event_queue=self.event_queue, engine=self.engine, dispatcher=self.dispatcher),
            14: SubdomainExecutor(event_queue=self.event_queue, engine=self.engine, dispatcher=self.dispatcher),
            15: PortScannerExecutor(event_queue=self.event_queue, engine=self.engine, dispatcher=self.dispatcher),
            16: MacExecutor(event_queue=self.event_queue, engine=self.engine, dispatcher=self.dispatcher),
        }

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
                                slot_title = SLOT_TITLES.get(slot)
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
                        placeholder="введите номер (1-30) или запрос цели...",
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

        if slot in SLOT_CONFIGS:
            self._selected_slot = slot
            cfg = SLOT_CONFIGS[slot]
            prompt.update(cfg["prompt"])
            status.update(f"[ выбор ] Модуль {slot} > {cfg['title']} активен. Введите данные цели...")
            cmd_input.placeholder = cfg["placeholder"]
        else:
            self._selected_slot = None
            prompt.update("Command / Slot > ")
            status.update(f"[ заглушка ] Слот {slot} > SOON (модуль в резерве)")
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

        # Автоматическое определение слота при отсутствии явного выбора
        slot = self._selected_slot
        if slot is None:
            if "@" in raw:
                slot = 3
            elif raw.startswith("+") or (raw.isdigit() and len(raw) in (10, 11, 12)):
                slot = 4 if len(raw) <= 12 and not raw.isdigit() else (6 if len(raw) in (10, 12) else 1)
            else:
                slot = 1

        status.update("[ ожидание ] Запрос обрабатывается...")
        target = TargetProfile(username=raw)
        asyncio.create_task(self._execute_scan(target, slot=slot))

    async def _execute_scan(self, target: TargetProfile, slot: int = 1) -> None:
        self._is_scanning = True
        status = self.query_one("#status_message", Static)
        save_btn = self.query_one("#save_html_button", Button)
        save_btn.display = False

        executor = self._executors.get(slot, self.nickname_executor)
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
                    status.update(f"[ готово ] Сессия {event.session_id}: сформировано отчетов: {len(event.report_paths)}")
                    save_btn.display = True
            except asyncio.TimeoutError:
                continue
            except Exception:
                break

        try:
            self._last_session_result = await scan_task
            found = self._last_session_result.found_count
            cfg = SLOT_CONFIGS.get(slot, {"title": "Scan"})
            status.update(
                f"[ готово ] {cfg['title']} {self._last_session_result.session_id} | Результатов: {found} | Нажмите '> сохранить HTML'"
            )
            save_btn.display = True
        except Exception as err:
            status.update(f"[ сбой ] Ошибка сканирования: {err}")
        finally:
            self._is_scanning = False

    async def action_save_html(self) -> None:
        if self._last_session_result is None:
            self.query_one("#status_message", Static).update("[ ошибка ] Нет результатов для экспорта")
            return

        status = self.query_one("#status_message", Static)
        status.update("[ экспорт ] Генерация HTML отчета...")
        try:
            reports = await self.dispatcher.export_all(self._last_session_result)
            html_report = next((r for r in reports if str(r).endswith(".html")), None)
            if html_report:
                status.update(f"[ готово ] Отчет сохранен: {html_report.name}")
                from epitaph.reporting.dispatcher import open_in_viewer
                opened = await asyncio.to_thread(open_in_viewer, html_report)
                if opened:
                    status.update(f"[ открыт ] Отчет открыт: {html_report.name}")
            else:
                status.update("[ готово ] Отчеты успешно сгенерированы")
        except Exception as err:
            status.update(f"[ сбой ] Ошибка сохранения HTML: {err}")
