from __future__ import annotations

from typing import Dict, List
from pydantic import BaseModel, ConfigDict, Field


class PortScanMetadata(BaseModel):
    # Модель обнаруженных сетевых служб и открытых TCP-портов
    model_config = ConfigDict(frozen=True)

    host: str
    scanned_ports_count: int
    open_ports: List[int] = Field(default_factory=list)
    banners: Dict[int, str] = Field(default_factory=dict)
