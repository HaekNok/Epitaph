# Экран главного меню TUI-интерфейса Epitaph с адаптивной версткой
from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.events import Resize
from textual.screen import Screen
from textual.widgets import Button, Input, Static

from epitaph.ui.widgets.banner import HeaderBanner
from epitaph.ui.widgets.menu_slot import MenuSlot


class MainScreen(Screen[None]):
    # Экран главного меню с поддержкой адаптивной одно- и трехколоночной сетки

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
                                yield MenuSlot(slot_number=slot_idx)

            with Vertical(id="footer_panel"):
                with Horizontal(id="action_bar"):
                    yield Button("> клавиатура", id="keyboard_button")
                    yield Static(id="action_spacer")
                    yield Button("[q] > выход", id="exit_button")
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
            command_input = self.query_one("#command_input", Input)
            command_input.focus()
            command_input.cursor_position = len(command_input.value)
        elif event.button.id == "exit_button":
            self.app.exit()

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
