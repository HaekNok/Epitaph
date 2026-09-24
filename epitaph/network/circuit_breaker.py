from datetime import datetime, timedelta, timezone
from epitaph.models.proxy import ProxyEntity


class CircuitBreaker:
    def __init__(self, failure_threshold: int = 3, cooldown_seconds: int = 300) -> None:
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds

    def should_trip(self, proxy: ProxyEntity) -> bool:
        return proxy.failure_count >= self.failure_threshold

    def calculate_cooldown(self) -> datetime:
        return datetime.now(timezone.utc) + timedelta(seconds=self.cooldown_seconds)

    def is_cooldown_expired(self, proxy: ProxyEntity) -> bool:
        if not proxy.cooldown_until:
            return True
        return datetime.now(timezone.utc) >= proxy.cooldown_until
