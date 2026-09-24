# Виджет верхней панели с ASCII-логотипом Epitaph
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static

ASCII_BANNER = """▓█████  ██▓███   ██▓▄▄▄█████▓ ▄▄▄       ██▓███   ██░ ██ 
▓█   ▀ ▓██░  ██▒▓██▒▓  ██▒ ▓▒▒████▄    ▓██░  ██▒▓██░ ██▒
▒███   ▓██░ ██▓▒▒██▒▒ ▓██░ ▒░▒██  ▀█▄  ▓██░ ██▓▒▒██▀▀██░
▒▓█  ▄ ▒██▄█▓▒ ▒░██░░ ▓██▓ ░ ░██▄▄▄▄██ ▒██▄█▓▒ ▒░▓█ ░██ 
░▒████▒▒██▒ ░  ░░██░  ▒██▒ ░  ▓█   ▓██▒▒██▒ ░  ░░▓█▒░██▓
░░ ▒░ ░▒▓▒░ ░  ░░▓    ▒ ░░    ▒▒   ▓▒█░▒▓▒░ ░  ░ ▒ ░░▒░▒
 ░ ░  ░░▒ ░      ▒ ░    ░      ▒   ▒▒ ░░▒ ░      ▒ ░▒░ ░
   ░   ░░        ▒ ░  ░        ░   ▒   ░░        ░  ░░ ░
   ░  ░          ░                 ░  ░          ░  ░  ░"""


class HeaderBanner(Widget):
    # Виджет отображения заголовка и метаданных проекта

    def compose(self) -> ComposeResult:
        # Размещение ASCII-символов и разделительной подстроки
        yield Static(ASCII_BANNER, id="ascii_art")
        yield Static(
            "─────────────────── [ MODULAR OSINT FRAMEWORK // CRIMSON NOIR ] ───────────────────",
            id="banner_subtitle",
        )
