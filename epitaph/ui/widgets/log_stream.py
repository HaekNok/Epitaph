from datetime import datetime
from textual.widgets import RichLog


class LogStreamWidget(RichLog):
    def write_line(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.write(f"[{timestamp}] {message}")
