from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, ConfigDict


class VehicleMetadata(BaseModel):
    # Модель транспортного средства и номерных знаков
    model_config = ConfigDict(frozen=True)

    raw_query: str
    plate_number: Optional[str] = None
    vin: Optional[str] = None
    region_code: Optional[str] = None
    country: str = "UA/RU/EU"
    is_valid: bool = True
