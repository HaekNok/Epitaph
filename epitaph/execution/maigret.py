from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional
import uuid

from epitaph.core.events import (
    CheckResultEvent,
    LogEvent,
    ProgressUpdateEvent,
    ScanCompletedEvent,
    StartScanEvent,
)
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.result import CheckResult, ScanSessionResult
from epitaph.models.target import TargetProfile
from epitaph.reporting.dispatcher import ReportDispatcher, get_default_report_dir

if TYPE_CHECKING:
    from epitaph.core.engine import ScanEngine

logger = logging.getLogger("epitaph.execution.maigret")

try:
    import maigret
    HAS_MAIGRET = True
except (ImportError, RuntimeError):
    maigret = None  # type: ignore
    HAS_MAIGRET = False


class MaigretExecutor:
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

    async def run_search(
        self, target: TargetProfile, output_dir: Optional[Path] = None
    ) -> ScanSessionResult:
        session_id = uuid.uuid4().hex[:8]
        start_time = datetime.now(timezone.utc)
        await self.event_queue.put(StartScanEvent(target=target, session_id=session_id))

        if HAS_MAIGRET and maigret is not None:
            try:
                return await self._run_native(target, session_id, start_time, output_dir)
            except Exception as err:
                logger.warning("Сбой нативного поиска Maigret: %s. Переключение на ScanEngine.", err)
                await self.event_queue.put(
                    LogEvent(message=f"Ошибка Maigret: {err}. Переключение на встроенный движок.", level="WARNING")
                )

        return await self.engine.run_scan(target, output_dir=output_dir)

    async def _run_native(
        self,
        target: TargetProfile,
        session_id: str,
        start_time: datetime,
        output_dir: Optional[Path],
    ) -> ScanSessionResult:
        await self.event_queue.put(LogEvent(message=f"Запуск Maigret сканирования для {target.username}."))

        def _search() -> List[Dict[str, Any]]:
            return list(maigret.search(username=target.username)) if hasattr(maigret, "search") else []

        raw_items = await asyncio.to_thread(_search)
        results: List[CheckResult] = []
        total = max(len(raw_items), 1)

        for idx, item in enumerate(raw_items, start=1):
            is_found = "FOUND" in str(item.get("status", "FOUND")).upper()
            res = CheckResult(
                platform_name=str(item.get("site_name", "Unknown")),
                target=target,
                status=DetectionStatus.FOUND if is_found else DetectionStatus.NOT_FOUND,
                profile_url=item.get("url_user"),
                response_time_ms=float(item.get("response_time", 0.0) or 0.0),
                execution_type=ExecutionType.HTTP,
                http_status_code=item.get("http_status"),
            )
            results.append(res)
            await self.event_queue.put(CheckResultEvent(result=res))
            await self.event_queue.put(ProgressUpdateEvent(completed=idx, total=total))

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
