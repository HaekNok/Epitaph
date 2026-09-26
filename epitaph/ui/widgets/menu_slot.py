# Виджеты слота меню и плашки выхода
from typing import Optional
from textual.message import Message
from textual.widgets import Static


class MenuSlot(Static):
    # Интерактивный виджет функционального слота

    can_focus = True

    class Selected(Message):
        # Событие активации слота меню
        def __init__(self, slot_number: int) -> None:
            self.slot_number = slot_number
            super().__init__()

    def __init__(self, slot_number: int, title: Optional[str] = None) -> None:
        self.slot_number = slot_number
        self.title = title
        if title:
            formatted_label = f"{slot_number:>2} > {title}"
        else:
            formatted_label = f"{slot_number:>2} > SOON"
        super().__init__(formatted_label, classes="menu_slot")

    def on_click(self) -> None:
        # Обработка нажатия указателя мыши на слот
        self.post_message(self.Selected(self.slot_number))

    def key_enter(self) -> None:
        # Обработка нажатия клавиши Enter при фокусе
        self.post_message(self.Selected(self.slot_number))


class ExitBadge(Static):
    # Кликабельный виджет выхода из интерфейса

    def on_click(self) -> None:
        # Завершение работы приложения при клике
        self.app.exit()
