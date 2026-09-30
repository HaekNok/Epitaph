from __future__ import annotations

from typing import Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class EmailDetectionMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)

    email: str
    platform: str
    exists: bool
    profile_url: Optional[str] = None
    masked_phone: Optional[str] = None
    masked_email: Optional[str] = None
    display_name: Optional[str] = None
    avatar_url: Optional[str] = None
    extra: Dict[str, object] = Field(default_factory=dict)
