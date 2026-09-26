import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional

from epitaph.core.events import CheckResultEvent, ProgressUpdateEvent, ScanCompletedEvent
from epitaph.core.scheduler import TaskScheduler
from epitaph.execution.base import BasePlatformChecker
from epitaph.execution.registry import CheckerRegistry
from epitaph.models.result import CheckResult, ScanSessionResult
from epitaph.models.target import TargetProfile
from epitaph.reporting.dispatcher import ReportDispatcher, get_default_report_dir


class ScanEngine:
    def __init__(
        self,
        scheduler: Optional[TaskScheduler] = None,
        dispatcher: Optional[ReportDispatcher] = None,
        event_queue: Optional[asyncio.Queue[Any]] = None,
    ) -> None:
        self.scheduler = scheduler or TaskScheduler()
        self.dispatcher = dispatcher or ReportDispatcher()
        self.event_queue = event_queue or asyncio.Queue()

    async def run_scan(
        self, target: TargetProfile, output_dir: Optional[Path] = None
    ) -> ScanSessionResult:
        session_id = uuid.uuid4().hex[:8]
        start_time = datetime.now(timezone.utc)
        checkers = CheckerRegistry.get_all_checkers()
        total = len(checkers)
        results: List[CheckResult] = []

        async def worker(checker: BasePlatformChecker) -> None:
            res = await self.scheduler.run_checker(checker, target)
            results.append(res)
            await self.event_queue.put(CheckResultEvent(result=res))
            await self.event_queue.put(
                ProgressUpdateEvent(completed=len(results), total=total)
            )

        async with asyncio.TaskGroup() as tg:
            for ch in checkers:
                tg.create_task(worker(ch))

        end_time = datetime.now(timezone.utc)
        session_result = ScanSessionResult(
            session_id=session_id,
            target=target,
            start_time=start_time,
            end_time=end_time,
            results=results,
        )

        target_out = output_dir or get_default_report_dir(session_id, target.username)
        reports = await self.dispatcher.export_all(session_result, target_out)
        await self.event_queue.put(
            ScanCompletedEvent(session_id=session_id, report_paths=reports)
        )

        return session_result
