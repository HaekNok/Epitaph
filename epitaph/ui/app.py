# Точка входа в TUI-интерфейс Epitaph
from textual.app import App

from epitaph.ui.screens.main_screen import MainScreen


class EpitaphApp(App[None]):
    # Главный класс приложения Textual с привязкой темы и экрана
    TITLE = "Epitaph OSINT Framework"
    SUB_TITLE = "Modular Intelligence Platform"
    CSS_PATH = "styles.tcss"

    BINDINGS = [
        ("q", "quit", "Выход"),
        ("ctrl+c", "quit", "Завершить работу"),
    ]

    def on_mount(self) -> None:
        # Монтирование главного экрана при старте приложения
        self.push_screen(MainScreen())
