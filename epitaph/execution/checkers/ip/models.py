from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, ConfigDict


class IpMetadata(BaseModel):
    # Модель сетевой геолокации и маршрутизации IP-адреса
    model_config = ConfigDict(frozen=True)

    ip: str
    ip_version: int
    is_private: bool
    is_bogon: bool
    reverse_dns: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    org: Optional[str] = None
