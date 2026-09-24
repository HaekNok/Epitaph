from textual.widgets import ProgressBar


class ScanProgressBar(ProgressBar):
    def update_progress(self, completed: int, total: int) -> None:
        self.update(total=total, progress=completed)
