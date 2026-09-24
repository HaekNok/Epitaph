from typing import Any, Dict
from pydantic import BaseModel, ConfigDict, Field


class TargetProfile(BaseModel):
    model_config = ConfigDict(frozen=True)

    username: str = Field(..., min_length=1, max_length=128)
    metadata: Dict[str, Any] = Field(default_factory=dict)
