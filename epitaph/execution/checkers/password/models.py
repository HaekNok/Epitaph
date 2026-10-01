from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class PasswordBreachMetadata(BaseModel):
    # Модель анализа утечек паролей и криптографической энтропии
    model_config = ConfigDict(frozen=True)

    hash_prefix: str
    is_compromised: bool
    breach_count: int
    entropy_bits: float
    strength_rating: str
