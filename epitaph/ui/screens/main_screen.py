# Точка входа в TUI-интерфейс Epitaph
from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Input, Static

from epitaph.ui.widgets.banner import HeaderBanner
from epitaph.ui.widgets.menu_slot import ExitBadge, MenuSlot


class MainScreen(Screen[None]):
    # Экран главного меню с 30 слотами и командной строкой

    def compose(self) -> ComposeResult:
        # Компоновка интерфейсных блоков главного экрана
        with Vertical(id="main_container"):
            yield HeaderBanner(id="header_banner")

            menu_frame = Vertical(id="menu_frame")
            menu_frame.border_title = "ДОСТУПНЫЕ МОДУЛИ"
            with menu_frame:
                with Horizontal(id="grid_container"):
                    # Разбиение 30 слотов на три равные колонки по 10 элементов
                    for col_idx in range(3):
                        with Vertical(classes="menu_column"):
                            start_slot = col_idx * 10 + 1
                            for slot_idx in range(start_slot, start_slot + 10):
                                yield MenuSlot(slot_number=slot_idx)

            with Vertical(id="footer_panel"):
                yield ExitBadge("[q] > выход", id="exit_badge")
                yield Static(
                    "[ ожидание ] Выберите номер слота или введите 'q' для выхода",
                    id="status_message",
                )
                with Horizontal(id="command_bar"):
                    yield Static("Select function number > ", id="prompt_label")
                    yield Input(
                        placeholder="введите номер (1-30) или 'q'...",
                        id="command_input",
                    )

    @on(MenuSlot.Selected)
    def handle_slot_selected(self, message: MenuSlot.Selected) -> None:
        # Заглушка события интерактивного выбора слота
        status = self.query_one("#status_message", Static)
        status.update(f"[ заглушка ] Слот {message.slot_number} > SOON (модуль в разработке)")

    @on(Input.Submitted, "#command_input")
    def handle_command_submitted(self, event: Input.Submitted) -> None:
        # Обработка команд в нижней терминальной строке
        raw_val = event.value.strip().lower()
        event.input.value = ""

        if raw_val in ("q", "quit", "exit", "выход"):
            self.app.exit()
            return

        if raw_val.isdigit() and 1 <= int(raw_val) <= 30:
            slot_num = int(raw_val)
            status = self.query_one("#status_message", Static)
            status.update(f"[ заглушка ] Выбран слот {slot_num} > SOON (модуль в разработке)")
        else:
            status = self.query_one("#status_message", Static)
            status.update("[ ошибка ] Введите число от 1 до 30 или 'q' для выхода")
