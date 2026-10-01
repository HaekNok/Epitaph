from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, ConfigDict


class BankCardMetadata(BaseModel):
    # Модель анализа платежной карты и банковского идентификатора BIN
    model_config = ConfigDict(frozen=True)

    masked_number: str
    bin_number: str
    payment_system: str
    is_luhn_valid: bool
    bank_name: Optional[str] = None
    card_type: str = "DEBIT/CREDIT"
