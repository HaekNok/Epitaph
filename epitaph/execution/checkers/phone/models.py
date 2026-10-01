from __future__ import annotations

from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field


class PhoneMetadata(BaseModel):
    # Модель телефонного номера и сотовой инфраструктуры
    model_config = ConfigDict(frozen=True)

    raw_phone: str
    cleaned_e164: str
    country: str
    country_code: str
    operator_name: Optional[str] = None
    region_name: Optional[str] = None
    line_type: str = "MOBILE"
    is_valid: bool = True
    whatsapp_url: Optional[str] = None
    viber_url: Optional[str] = None
    telegram_url: Optional[str] = None
    extra_data: Dict[str, Any] = Field(default_factory=dict)
