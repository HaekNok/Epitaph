from textual.app import App
from epitaph.ui.screens.main_screen import MainScreen


class EpitaphApp(App[None]):
    TITLE = "Epitaph OSINT Scanner"
    BINDINGS = [
        ("q", "quit", "Выход"),
    ]

    def on_mount(self) -> None:
        self.push_screen(MainScreen())
