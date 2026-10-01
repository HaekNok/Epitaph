from __future__ import annotations

from typing import List
from pydantic import BaseModel, ConfigDict, Field


class SubdomainMetadata(BaseModel):
    # Модель обнаруженных поддоменов в логах прозрачности сертификатов
    model_config = ConfigDict(frozen=True)

    domain: str
    subdomains_count: int
    subdomains: List[str] = Field(default_factory=list)
