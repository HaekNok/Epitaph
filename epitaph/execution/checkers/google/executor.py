import asyncio
from datetime import datetime, timezone
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, List, Optional
import uuid

from epitaph.core.events import (
    CheckResultEvent,
    LogEvent,
    ProgressUpdateEvent,
    ScanCompletedEvent,
    StartScanEvent,
)
from epitaph.execution.checkers.google.checker import GoogleAccountChecker
from epitaph.models.result import CheckResult, ScanSessionResult
from epitaph.models.target import TargetProfile
from epitaph.reporting.dispatcher import ReportDispatcher, get_default_report_dir

if TYPE_CHECKING:
    from epitaph.core.engine import ScanEngine

logger = logging.getLogger("epitaph.execution.checkers.google.executor")


class GoogleExecutor:
    def __init__(
        self,
        event_queue: Optional[asyncio.Queue[Any]] = None,
        engine: Optional["ScanEngine"] = None,
        dispatcher: Optional[ReportDispatcher] = None,
    ) -> None:
        self.event_queue = event_queue or asyncio.Queue()
        self.dispatcher = dispatcher or ReportDispatcher()
        if engine is None:
            from epitaph.core.engine import ScanEngine
            self.engine = ScanEngine(event_queue=self.event_queue, dispatcher=self.dispatcher)
        else:
            self.engine = engine
        self.checker = GoogleAccountChecker()

    async def run_search(
        self, target: TargetProfile, output_dir: Optional[Path] = None
    ) -> ScanSessionResult:
        session_id = uuid.uuid4().hex[:8]
        start_time = datetime.now(timezone.utc)
        await self.event_queue.put(StartScanEvent(target=target, session_id=session_id))
        await self.event_queue.put(
            LogEvent(message=f"Запуск разведки Google-профиля: {target.username}...", level="INFO")
        )

        res = await self.engine.scheduler.run_checker(self.checker, target)
        await self.event_queue.put(CheckResultEvent(result=res))
        await self.event_queue.put(ProgressUpdateEvent(completed=1, total=1))

        session_result = ScanSessionResult(
            session_id=session_id,
            target=target,
            start_time=start_time,
            end_time=datetime.now(timezone.utc),
            results=[res],
        )

        target_out = output_dir or get_default_report_dir(session_id, target.username)
        reports = await self.dispatcher.export_all(session_result, target_out)
        await self.event_queue.put(ScanCompletedEvent(session_id=session_id, report_paths=reports))

        return session_result
