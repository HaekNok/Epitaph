# Валидатор и поисковый координатор юридических лиц и ОГРН (Слот 9)
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
from epitaph.execution.checkers.organization.models import OrganizationMetadata
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.result import CheckResult, ScanSessionResult
from epitaph.models.target import TargetProfile
from epitaph.reporting.dispatcher import ReportDispatcher, get_default_report_dir

if TYPE_CHECKING:
    from epitaph.core.engine import ScanEngine

logger = logging.getLogger("epitaph.execution.checkers.organization.executor")


class OrganizationExecutor:
    # Исполнитель проверки ОГРН 13 знаков и ОГРНИП 15 знаков
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

    def _validate_ogrn(self, raw: str) -> OrganizationMetadata:
        # Проверка контрольного разряда ОГРН по остатку деления
        digits = re.sub(r"\D+", "", raw)
        if len(digits) == 13:
            num = int(digits[:12])
            ctrl = (num % 11) % 10
            is_valid = ctrl == int(digits[12])
            return OrganizationMetadata(
                query=raw,
                ogrn=digits,
                is_valid_ogrn=is_valid,
                org_type="Юридическое лицо (ОГРН 13 цифр)",
            )
        if len(digits) == 15:
            num = int(digits[:14])
            ctrl = (num % 13) % 10
            is_valid = ctrl == int(digits[14])
            return OrganizationMetadata(
                query=raw,
                ogrn=digits,
                is_valid_ogrn=is_valid,
                org_type="Индивидуальный предприниматель (ОГРНИП 15 цифр)",
            )
        return OrganizationMetadata(
            query=raw,
            ogrn=digits if digits else None,
            is_valid_ogrn=False,
            org_type="Наименование организации / Невалидный ОГРН",
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
        meta = self._validate_ogrn(target.username)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        status = DetectionStatus.FOUND if meta.is_valid_ogrn else DetectionStatus.NOT_FOUND
        res = CheckResult(
            platform_name="Organization Registry",
            target=target,
            status=status,
            response_time_ms=elapsed_ms,
            execution_type=ExecutionType.HTTP,
            extracted_data=meta.model_dump(),
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
