from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class SnilsMetadata(BaseModel):
    # Модель верификации страхового номера лицевого счета
    model_config = ConfigDict(frozen=True)

    snils: str
    formatted_snils: str
    is_valid: bool
    checksum: int
