# Координатор OSINT-поиска персоналий по ФИО (Слот 5)
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
from epitaph.execution.checkers.fullname.models import PersonMetadata
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.result import CheckResult, ScanSessionResult
from epitaph.models.target import TargetProfile
from epitaph.reporting.dispatcher import ReportDispatcher, get_default_report_dir

if TYPE_CHECKING:
    from epitaph.core.engine import ScanEngine

logger = logging.getLogger("epitaph.execution.checkers.fullname.executor")


class FullNameExecutor:
    # Исполнитель синтаксического анализа и разведки по ФИО
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

    def _parse_fio(self, raw: str) -> Optional[PersonMetadata]:
        # Разбор ФИО на составные компоненты с нормализацией регистра
        cleaned = re.sub(r"\s+", " ", raw.strip())
        parts = [p.capitalize() for p in cleaned.split(" ") if p]
        if len(parts) < 2:
            return None

        last_name = parts[0]
        first_name = parts[1]
        middle_name = parts[2] if len(parts) >= 3 else None
        norm_full = " ".join(parts)

        gender = None
        if middle_name:
            if middle_name.endswith(("вич", "ович", "евич")):
                gender = "MALE"
            elif middle_name.endswith(("вна", "овна", "евна")):
                gender = "FEMALE"

        queries = [
            f'"{norm_full}"',
            f'"{last_name} {first_name}"',
        ]
        return PersonMetadata(
            raw_query=raw,
            last_name=last_name,
            first_name=first_name,
            middle_name=middle_name,
            sanitized_full_name=norm_full,
            gender_estimate=gender,
            search_queries=queries,
        )

    async def run_search(
        self,
        target: TargetProfile,
        output_dir: Optional[Path] = None,
    ) -> ScanSessionResult:
        session_id = uuid.uuid4().hex[:8]
        start_time = datetime.now(timezone.utc)
        await self.event_queue.put(StartScanEvent(target=target, session_id=session_id))
        await self.event_queue.put(
            LogEvent(message=f"Парсинг ФИО для объекта '{target.username}'...", level="INFO")
        )

        t0 = time.perf_counter()
        meta = self._parse_fio(target.username)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        if meta is None:
            res = CheckResult(
                platform_name="FullName Parser",
                target=target,
                status=DetectionStatus.ERROR,
                response_time_ms=elapsed_ms,
                execution_type=ExecutionType.HTTP,
                error_message="Требуется минимум Фамилия и Имя для анализа",
            )
        else:
            res = CheckResult(
                platform_name="FullName Parser",
                target=target,
                status=DetectionStatus.FOUND,
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
