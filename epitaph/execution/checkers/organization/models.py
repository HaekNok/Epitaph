from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, ConfigDict


class OrganizationMetadata(BaseModel):
    # Модель реестровых данных юридического лица
    model_config = ConfigDict(frozen=True)

    query: str
    ogrn: Optional[str] = None
    inn: Optional[str] = None
    kpp: Optional[str] = None
    is_valid_ogrn: bool = False
    org_type: str = "Юридическое лицо"
