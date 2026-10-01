from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class PersonMetadata(BaseModel):
    # Модель структурированных данных персоны
    model_config = ConfigDict(frozen=True)

    raw_query: str
    last_name: str
    first_name: str
    middle_name: Optional[str] = None
    sanitized_full_name: str
    gender_estimate: Optional[str] = None
    search_queries: List[str] = Field(default_factory=list)
    records: List[Dict[str, Any]] = Field(default_factory=list)
