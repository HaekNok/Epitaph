# Экран главного меню TUI-интерфейса Epitaph с поддержкой Maigret
import asyncio
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
from epitaph.execution.maigret import MaigretExecutor
from epitaph.models.target import TargetProfile
from epitaph.ui.widgets.banner import HeaderBanner
from epitaph.ui.widgets.menu_slot import MenuSlot


class MainScreen(Screen[None]):
    # Экран главного меню с поддержкой слотов и поиска Maigret

    def __init__(self) -> None:
        super().__init__()
        self.event_queue: asyncio.Queue[Any] = asyncio.Queue()
        self.maigret_executor = MaigretExecutor(event_queue=self.event_queue)
        self._is_scanning = False
        self._selected_slot: Optional[int] = None

    def compose(self) -> ComposeResult:
        # Компоновка интерфейсных блоков главного экрана
        with Vertical(id="main_container"):
            yield HeaderBanner(id="header_banner")

            menu_frame = Vertical(id="menu_frame")
            menu_frame.border_title = "ДОСТУПНЫЕ МОДУЛИ"
            with menu_frame:
                with Horizontal(id="grid_container"):
                    # Разбиение 30 слотов на колонки с адаптивным поведением
                    for col_idx in range(3):
                        with Vertical(classes="menu_column"):
                            start_slot = col_idx * 10 + 1
                            for slot_idx in range(start_slot, start_slot + 10):
                                if slot_idx == 1:
                                    yield MenuSlot(slot_number=slot_idx, title="Nickname")
                                else:
                                    yield MenuSlot(slot_number=slot_idx)

            with Vertical(id="footer_panel"):
                with Horizontal(id="action_bar"):
                    yield Button("> клавиатура", id="keyboard_button")
                    yield Static(id="action_spacer")
                    yield Button("[q] > выход", id="exit_button")
                yield Static(
                    "[ ожидание ] Выберите слот касанием или введите номер модуля",
                    id="status_message",
                )
                with Horizontal(id="command_bar"):
                    yield Static("Command / Slot > ", id="prompt_label")
                    yield Input(
                        placeholder="введите номер (1-30) или никнейм цели...",
                        id="command_input",
                    )

    def on_mount(self) -> None:
        # Установка адаптивной геометрии при первоначальном монтировании экрана
        self._apply_responsive_layout(self.size.width)

    def on_resize(self, event: Resize) -> None:
        # Реакция на изменение размеров терминала в рантайме
        self._apply_responsive_layout(event.size.width)

    def _apply_responsive_layout(self, width: int) -> None:
        # Переключение между трехколоночным и одноколоночным представлением
        is_compact = width < 80
        try:
            container = self.query_one("#main_container")
            container.set_class(is_compact, "compact-layout")
            banner = self.query_one("#header_banner", HeaderBanner)
            banner.update_banner(width)
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        # Обработка нажатий на функциональные кнопки нижней панели
        if event.button.id == "keyboard_button":
            self.action_request_keyboard()
        elif event.button.id == "exit_button":
            self.app.exit()

    def action_request_keyboard(self) -> None:
        # Сброс режима отслеживания мыши через драйвер приложения Textual
        command_input = self.query_one("#command_input", Input)
        command_input.focus()
        command_input.cursor_position = len(command_input.value)

        driver = getattr(self.app, "_driver", None)
        seq = "[?1000l[?1002l[?1003l[?1006l"
        if driver and hasattr(driver, "write"):
            driver.write(seq)
        else:
            try:
                sys.stdout.write(seq)
                sys.stdout.flush()
            except Exception:
                pass

        status = self.query_one("#status_message", Static)
        status.update("[ клавиатура ] Коснитесь экрана для IME или нажмите VolUp+K")

        # Автоматическое восстановление захвата мыши через 3 секунды
        self.set_timer(3.0, self._restore_mouse_tracking)

    def _restore_mouse_tracking(self) -> None:
        # Восстановление режима отслеживания мыши через драйвер Textual
        driver = getattr(self.app, "_driver", None)
        seq = "[?1000h[?1002h[?1006h"
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
        # Мгновенное восстановление мыши при начале ввода текста
        self._restore_mouse_tracking()

    def _select_slot(self, slot_number: int) -> None:
        # Переключение активного слота меню и адаптация приглашения ввода
        command_input = self.query_one("#command_input", Input)
        prompt_label = self.query_one("#prompt_label", Static)
        status = self.query_one("#status_message", Static)

        if slot_number == 1:
            self._selected_slot = 1
            prompt_label.update("Target Nickname > ")
            status.update("[ выбор ] Модуль 1. Nickname активен. Введите никнейм цели...")
            command_input.placeholder = "введите целевой никнейм или 'q' для выхода..."
            command_input.focus()
        else:
            self._selected_slot = None
            prompt_label.update("Command / Slot > ")
            status.update(f"[ заглушка ] Слот {slot_number} > SOON (модуль в разработке)")
            command_input.placeholder = "введите номер слота (1-30) или 'q' для выхода..."
            command_input.focus()

    @on(MenuSlot.Selected)
    def handle_slot_selected(self, message: MenuSlot.Selected) -> None:
        # Обработка интерактивного выбора слота касанием или кликом мыши
        self._select_slot(message.slot_number)

    @on(Input.Submitted, "#command_input")
    def handle_command_submitted(self, event: Input.Submitted) -> None:
        # Обработка команд терминальной строки и запуск фонового сканирования
        raw_val = event.value.strip()
        event.input.value = ""

        if raw_val.lower() in ("q", "quit", "exit", "выход"):
            self.app.exit()
            return

        if not raw_val:
            return

        # Проверка числового ввода для активации слота
        if raw_val.isdigit() and 1 <= int(raw_val) <= 30:
            self._select_slot(int(raw_val))
            return

        if self._is_scanning:
            status = self.query_one("#status_message", Static)
            status.update("[ ошибка ] Сканирование уже выполняется...")
            return

        # Запуск сканирования для активного слота поиска
        target = TargetProfile(username=raw_val)
        asyncio.create_task(self._execute_scan(target))

    async def _execute_scan(self, target: TargetProfile) -> None:
        # Асинхронное выполнение сканирования Maigret без блокировки интерфейса
        self._is_scanning = True
        status = self.query_one("#status_message", Static)
        status.update(f"[ старт ] Поиск профиля: {target.username}...")

        scan_task = asyncio.create_task(self.maigret_executor.run_search(target))

        while not scan_task.done() or not self.event_queue.empty():
            try:
                event = await asyncio.wait_for(
                    self.event_queue.get(), timeout=0.1
                )
                if isinstance(event, CheckResultEvent):
                    status.update(
                        f"[ {event.result.platform_name} ] {event.result.status.value}"
                    )
                elif isinstance(event, ProgressUpdateEvent):
                    status.update(
                        f"[ прогресс ] Завершено: {event.completed} из {event.total}"
                    )
                elif isinstance(event, LogEvent):
                    status.update(f"[ лог ] {event.message}")
                elif isinstance(event, ScanCompletedEvent):
                    report_count = len(event.report_paths)
                    status.update(
                        f"[ готово ] Сессия {event.session_id}: сохранено отчетов: {report_count}"
                    )
            except asyncio.TimeoutError:
                continue
            except Exception:
                break

        try:
            await scan_task
        except Exception as exc:
            status.update(f"[ сбой ] Ошибка сканирования: {exc}")
        finally:
            self._is_scanning = False
