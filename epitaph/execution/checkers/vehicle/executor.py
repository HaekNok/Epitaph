# Валидатор и анализатор госномеров автотранспорта и VIN (Слот 8)
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
from epitaph.execution.checkers.vehicle.models import VehicleMetadata
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.result import CheckResult, ScanSessionResult
from epitaph.models.target import TargetProfile
from epitaph.reporting.dispatcher import ReportDispatcher, get_default_report_dir

if TYPE_CHECKING:
    from epitaph.core.engine import ScanEngine

logger = logging.getLogger("epitaph.execution.checkers.vehicle.executor")


class VehicleExecutor:
    # Исполнитель парсинга номерных знаков и VIN-кодов
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

    def _parse_vehicle(self, raw: str) -> VehicleMetadata:
        # Синтаксический разбор госномеров ГОСТ, ДСТУ и 17-значного VIN
        clean = re.sub(r"[\s\-_]+", "", raw.upper())
        if len(clean) == 17 and re.match(r"^[A-HJ-NPR-Z0-9]{17}$", clean):
            return VehicleMetadata(
                raw_query=raw,
                vin=clean,
                country="Международный (VIN)",
                is_valid=True,
            )

        ua_match = re.match(r"^([A-Z]{2})(\d{4})([A-Z]{2})$", clean)
        if ua_match:
            return VehicleMetadata(
                raw_query=raw,
                plate_number=clean,
                region_code=ua_match.group(1),
                country="Украина (ДСТУ)",
                is_valid=True,
            )

        ru_match = re.match(r"^([АВЕКМНОРСТУХA-Z])(\d{3})([АВЕКМНОРСТУХA-Z]{2})(\d{2,3})$", clean)
        if ru_match:
            return VehicleMetadata(
                raw_query=raw,
                plate_number=clean,
                region_code=ru_match.group(4),
                country="РФ (ГОСТ)",
                is_valid=True,
            )

        return VehicleMetadata(
            raw_query=raw,
            is_valid=False,
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
        meta = self._parse_vehicle(target.username)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        status = DetectionStatus.FOUND if meta.is_valid else DetectionStatus.ERROR
        res = CheckResult(
            platform_name="Vehicle Identification",
            target=target,
            status=status,
            response_time_ms=elapsed_ms,
            execution_type=ExecutionType.HTTP,
            extracted_data=meta.model_dump(),
            error_message=None if meta.is_valid else "Синтаксис госномера или VIN не распознан",
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
