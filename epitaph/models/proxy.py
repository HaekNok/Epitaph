from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field
from epitaph.models.base import ProxyProtocol


class ProxyEntity(BaseModel):
    model_config = ConfigDict(frozen=True)

    host: str
    port: int = Field(..., ge=1, le=65535)
    protocol: ProxyProtocol = ProxyProtocol.HTTP
    username: Optional[str] = None
    password: Optional[str] = None
    latency_ms: float = 0.0
    failure_count: int = Field(default=0, ge=0)
    is_active: bool = True
    cooldown_until: Optional[datetime] = None

    @property
    def url(self) -> str:
        auth = f"{self.username}:{self.password}@" if self.username and self.password else ""
        return f"{self.protocol}://{auth}{self.host}:{self.port}"
