from __future__ import annotations

from typing import Any, Dict, List
from pydantic import BaseModel, ConfigDict, Field


class CookieAuditMetadata(BaseModel):
    # Модель аудита безопасности сессионных куки
    model_config = ConfigDict(frozen=True)

    total_parsed: int
    secure_count: int
    httponly_count: int
    samesite_strict_count: int
    risk_level: str
    cookies_list: List[Dict[str, Any]] = Field(default_factory=list)
