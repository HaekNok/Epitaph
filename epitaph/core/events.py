from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict
from epitaph.models.result import CheckResult
from epitaph.models.target import TargetProfile


@dataclass(frozen=True)
class StartScanEvent:
    target: TargetProfile
    session_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class CheckResultEvent:
    result: CheckResult


@dataclass(frozen=True)
class ProgressUpdateEvent:
    completed: int
    total: int


@dataclass(frozen=True)
class LogEvent:
    message: str
    level: str = "INFO"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class ScanCompletedEvent:
    session_id: str
    report_paths: Dict[str, Path]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
