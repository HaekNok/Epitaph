# Модели спецификаций сервисов и правил проверки профилей
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CheckType(str, Enum):
    # Метод проверки существования аккаунта на платформе
    STATUS_CODE = "status_code"
    MESSAGE = "message"
    RESPONSE_URL = "response_url"


class SiteDefinition(BaseModel):
    # Декларативная спецификация целевого сервиса для OSINT-поиска

    name: str
    url: str
    url_probe: Optional[str] = None
    check_type: CheckType = CheckType.STATUS_CODE
    error_code: Optional[int] = 404
    error_message: Optional[str] = None
    presence_strings: List[str] = Field(default_factory=list)
    absence_strings: List[str] = Field(default_factory=list)
    error_url: Optional[str] = None
    regex_check: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    rate_limit_delay: float = 0.0
    category: str = "general"
    disabled: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SiteDefinition":
        # Создание и валидация экземпляра с поддержкой разных версий Pydantic
        if hasattr(cls, "model_validate"):
            return cls.model_validate(data)  # type: ignore[no-any-return]
        return cls.parse_obj(data)  # type: ignore[no-any-return]
