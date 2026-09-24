from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.target import TargetProfile


class CheckResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    platform_name: str
    target: TargetProfile
    status: DetectionStatus
    profile_url: Optional[str] = None
    response_time_ms: float = Field(default=0.0, ge=0.0)
    execution_type: ExecutionType
    http_status_code: Optional[int] = None
    extracted_data: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScanSessionResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    session_id: str
    target: TargetProfile
    start_time: datetime
    end_time: datetime
    results: List[CheckResult] = Field(default_factory=list)

    @property
    def total_scanned(self) -> int:
        return len(self.results)

    @property
    def found_count(self) -> int:
        return sum(1 for r in self.results if r.status == DetectionStatus.FOUND)
