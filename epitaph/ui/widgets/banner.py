# Виджет верхней панели с адаптивным ASCII-логотипом Epitaph
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static

ASCII_BANNER_FULL = """▓█████  ██▓███   ██▓▄▄▄█████▓ ▄▄▄       ██▓███   ██░ ██ 
▓█   ▀ ▓██░  ██▒▓██▒▓  ██▒ ▓▒▒████▄    ▓██░  ██▒▓██░ ██▒
▒███   ▓██░ ██▓▒▒██▒▒ ▓██░ ▒░▒██  ▀█▄  ▓██░ ██▓▒▒██▀▀██░
▒▓█  ▄ ▒██▄█▓▒ ▒░██░░ ▓██▓ ░ ░██▄▄▄▄██ ▒██▄█▓▒ ▒░▓█ ░██ 
░▒████▒▒██▒ ░  ░░██░  ▒██▒ ░  ▓█   ▓██▒▒██▒ ░  ░░▓█▒░██▓
░░ ▒░ ░▒▓▒░ ░  ░░▓    ▒ ░░    ▒▒   ▓▒█░▒▓▒░ ░  ░ ▒ ░░▒░▒
 ░ ░  ░░▒ ░      ▒ ░    ░      ▒   ▒▒ ░░▒ ░      ▒ ░▒░ ░
   ░   ░░        ▒ ░  ░        ░   ▒   ░░        ░  ░░ ░
   ░  ░          ░                 ░  ░          ░  ░  ░"""

ASCII_BANNER_COMPACT = """┌────────────────────────────────────┐
│      E P I T A P H   O S I N T     │
└────────────────────────────────────┘"""


class HeaderBanner(Widget):
    # Виджет отображения заголовка с адаптацией под ширину терминала

    def compose(self) -> ComposeResult:
        # Размещение ASCII-символов и разделительной подстроки
        yield Static(ASCII_BANNER_FULL, id="ascii_art")
        yield Static(
            "─────────────────── [ MODULAR OSINT FRAMEWORK // TGK: EpitaphFramework ] ───────────────────",
            id="banner_subtitle",
        )

    def update_banner(self, width: int) -> None:
        # Адаптивное обновление баннера под текущую ширину окна
        try:
            ascii_widget = self.query_one("#ascii_art", Static)
            subtitle_widget = self.query_one("#banner_subtitle", Static)

            if width >= 60:
                ascii_widget.update(ASCII_BANNER_FULL)
            else:
                ascii_widget.update(ASCII_BANNER_COMPACT)

            if width >= 80:
                decor_len = max(2, (width - 56) // 2)
                subtitle_widget.update(
                    f"{'─' * decor_len} [ MODULAR OSINT FRAMEWORK // TGK: EpitaphFramework ] {'─' * decor_len}"
                )
            elif width >= 58:
                subtitle_widget.update("[ MODULAR OSINT FRAMEWORK // TGK: EpitaphFramework ]")
            else:
                subtitle_widget.update("[ EPITAPH OSINT ]")
        except Exception:
            pass
