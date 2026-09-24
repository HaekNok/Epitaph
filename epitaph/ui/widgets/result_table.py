from textual.widgets import DataTable
from epitaph.models.result import CheckResult


class ResultTableWidget(DataTable):
    def on_mount(self) -> None:
        self.add_columns("Платформа", "Статус", "Профиль", "Время (мс)")

    def add_result(self, result: CheckResult) -> None:
        self.add_row(
            result.platform_name,
            str(result.status),
            result.profile_url or "-",
            f"{result.response_time_ms:.1f}",
        )

    def clear_results(self) -> None:
        self.clear()
