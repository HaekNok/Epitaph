from typing import Optional
from textual.message import Message
from textual.widgets import Static


class MenuSlot(Static):
    can_focus = True

    class Selected(Message):
        def __init__(self, slot_number: int) -> None:
            self.slot_number = slot_number
            super().__init__()

    def __init__(self, slot_number: int, title: Optional[str] = None) -> None:
        self.slot_number = slot_number
        self.title = title
        if title:
            clean = title.strip()
            if clean.startswith(f"{slot_number} >") or clean.startswith(f"{slot_number:>2} >"):
                label = clean
            else:
                label = f"{slot_number:>2} > {clean}"
        else:
            label = f"{slot_number:>2} > SOON"
        super().__init__(label, classes="menu_slot")

    def on_click(self) -> None:
        self.post_message(self.Selected(self.slot_number))

    def key_enter(self) -> None:
        self.post_message(self.Selected(self.slot_number))


class ExitBadge(Static):
    def on_click(self) -> None:
        self.app.exit()
