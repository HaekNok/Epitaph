from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, ConfigDict


class MacMetadata(BaseModel):
    # Модель анализа аппаратного MAC-адреса
    model_config = ConfigDict(frozen=True)

    raw_mac: str
    normalized_mac: str
    oui_prefix: str
    vendor: Optional[str] = None
    is_multicast: bool = False
    is_locally_administered: bool = False
    is_valid: bool = True
