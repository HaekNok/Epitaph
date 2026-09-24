# Экран главного меню TUI-интерфейса Epitaph с адаптивной версткой
import sys
from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.events import Resize
from textual.screen import Screen
from textual.widgets import Button, Input, Static

from epitaph.ui.widgets.banner import HeaderBanner
from epitaph.ui.widgets.menu_slot import MenuSlot


class MainScreen(Screen[None]):
    # Экран главного меню с поддержкой адаптивной сетки и мобильного ввода

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
                    "[ ожидание ] Выберите слот касанием или введите номер",
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
            self.action_request_keyboard()
        elif event.button.id == "exit_button":
            self.app.exit()

    def action_request_keyboard(self) -> None:
        # Запрос экранной клавиатуры через сброс захвата мыши и статусное уведомление
        command_input = self.query_one("#command_input", Input)
        command_input.focus()
        command_input.cursor_position = len(command_input.value)

        # Временный сброс захвата мыши для обработки последующего касания в Termux
        try:
            sys.stdout.write("[?1000l[?1002l[?1003l[?1006l")
            sys.stdout.flush()
        except Exception:
            pass

        status = self.query_one("#status_message", Static)
        status.update("[ клавиатура ] Коснитесь экрана для IME или нажмите VolUp+K")

        # Автоматическое восстановление захвата мыши через 3 секунды
        self.set_timer(3.0, self._restore_mouse_tracking)

    def _restore_mouse_tracking(self) -> None:
        # Восстановление режима отслеживания мыши для работы TUI
        try:
            sys.stdout.write("[?1000h[?1002h[?1006h")
            sys.stdout.flush()
        except Exception:
            pass

    @on(Input.Changed, "#command_input")
    def handle_input_changed(self) -> None:
        # Мгновенное восстановление мыши при начале ввода текста
        self._restore_mouse_tracking()

    @on(MenuSlot.Selected)
    def handle_slot_selected(self, message: MenuSlot.Selected) -> None:
        # Интерактивный выбор слота без необходимости использования клавиатуры
        command_input = self.query_one("#command_input", Input)
        command_input.value = str(message.slot_number)
        status = self.query_one("#status_message", Static)
        status.update(f"[ выбор ] Слот {message.slot_number} активирован (модуль в разработке)")

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
            status.update(f"[ выбор ] Запуск слота {slot_num} > SOON (модуль в разработке)")
        else:
            status = self.query_one("#status_message", Static)
            status.update("[ ошибка ] Введите число от 1 до 30 или 'q' для выхода")
