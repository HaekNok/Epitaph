# Валидатор и верификатор номеров СНИЛС (Слот 7)
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
from pathlib import Path
import re
import time
from typing import TYPE_CHECKING, Any, Optional
import uuid

from epitaph.core.events import (
    CheckResultEvent,
    LogEvent,
    ProgressUpdateEvent,
    ScanCompletedEvent,
    StartScanEvent,
)
from epitaph.execution.checkers.snils.models import SnilsMetadata
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.result import CheckResult, ScanSessionResult
from epitaph.models.target import TargetProfile
from epitaph.reporting.dispatcher import ReportDispatcher, get_default_report_dir

if TYPE_CHECKING:
    from epitaph.core.engine import ScanEngine

logger = logging.getLogger("epitaph.execution.checkers.snils.executor")


class SnilsExecutor:
    # Исполнитель алгоритмической проверки контрольной суммы СНИЛС
    def __init__(
        self,
        event_queue: Optional[asyncio.Queue[Any]] = None,
        engine: Optional[ScanEngine] = None,
        dispatcher: Optional[ReportDispatcher] = None,
    ) -> None:
        self.event_queue = event_queue or asyncio.Queue()
        self.dispatcher = dispatcher or ReportDispatcher()
        if engine is None:
            from epitaph.core.engine import ScanEngine
            self.engine = ScanEngine(event_queue=self.event_queue, dispatcher=self.dispatcher)
        else:
            self.engine = engine

    def _validate_snils(self, raw_snils: str) -> SnilsMetadata:
        # Проверка алгоритма ПФР sum(digit * pos) % 101 для 11 цифр СНИЛС
        digits = re.sub(r"\D+", "", raw_snils)
        if len(digits) != 11:
            return SnilsMetadata(
                snils=digits,
                formatted_snils=raw_snils,
                is_valid=False,
                checksum=0,
            )

        num_part = digits[:9]
        if int(num_part) <= 1001998:
            return SnilsMetadata(
                snils=digits,
                formatted_snils=raw_snils,
                is_valid=False,
                checksum=0,
            )

        check_val = int(digits[9:])
        total = sum(int(num_part[i]) * (9 - i) for i in range(9))

        if total < 100:
            expected = total
        elif total in (100, 101):
            expected = 0
        else:
            rem = total % 101
            expected = 0 if rem in (100, 101) else rem

        is_valid = (expected == check_val)
        fmt = f"{digits[:3]}-{digits[3:6]}-{digits[6:9]} {digits[9:]}"
        return SnilsMetadata(
            snils=digits,
            formatted_snils=fmt,
            is_valid=is_valid,
            checksum=expected,
        )

    async def run_search(
        self,
        target: TargetProfile,
        output_dir: Optional[Path] = None,
    ) -> ScanSessionResult:
        session_id = uuid.uuid4().hex[:8]
        start_time = datetime.now(timezone.utc)
        await self.event_queue.put(StartScanEvent(target=target, session_id=session_id))

        t0 = time.perf_counter()
        meta = self._validate_snils(target.username)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        status = DetectionStatus.FOUND if meta.is_valid else DetectionStatus.ERROR
        res = CheckResult(
            platform_name="PFR SNILS Validator",
            target=target,
            status=status,
            response_time_ms=elapsed_ms,
            execution_type=ExecutionType.HTTP,
            extracted_data=meta.model_dump(),
            error_message=None if meta.is_valid else "Контрольная сумма СНИЛС не сошлась",
        )

        results = [res]
        await self.event_queue.put(CheckResultEvent(result=res))
        await self.event_queue.put(ProgressUpdateEvent(completed=1, total=1))

        session_result = ScanSessionResult(
            session_id=session_id,
            target=target,
            start_time=start_time,
            end_time=datetime.now(timezone.utc),
            results=results,
        )
        target_out = output_dir or get_default_report_dir(session_id, target.username)
        reports = await self.dispatcher.export_all(session_result, target_out)
        await self.event_queue.put(ScanCompletedEvent(session_id=session_id, report_paths=reports))
        return session_result
