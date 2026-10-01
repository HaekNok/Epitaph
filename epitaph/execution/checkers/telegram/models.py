from __future__ import annotations

from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field


class TelegramProfileMetadata(BaseModel):
    # Модель структурированных метаданных профиля Telegram
    model_config = ConfigDict(frozen=True)

    target_query: str
    username: Optional[str] = None
    telegram_id: Optional[int] = None
    title: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    is_channel: bool = False
    is_bot: bool = False
    subscribers_count: Optional[int] = None
    raw_data: Dict[str, Any] = Field(default_factory=dict)
