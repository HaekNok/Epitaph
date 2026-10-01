from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, ConfigDict


class InnMetadata(BaseModel):
    # Модель верификации индивидуального налогового номера
    model_config = ConfigDict(frozen=True)

    inn: str
    inn_type: str
    is_valid: bool
    region_code: Optional[str] = None
    checksum_valid: bool = False
