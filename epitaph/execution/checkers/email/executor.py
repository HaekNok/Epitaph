"""Координатор сканирования по email для Слота 2 (Google OSINT + Holehe Services)."""
from __future__ import annotations

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
from epitaph.execution.checkers.email.registry import EmailCheckerRegistry
import epitaph.execution.checkers.email.services  # noqa: F401 - регистрация сервисов в реестре
from epitaph.execution.checkers.google.checker import GoogleAccountChecker
from epitaph.models.result import CheckResult, ScanSessionResult
from epitaph.models.target import TargetProfile
from epitaph.reporting.dispatcher import ReportDispatcher, get_default_report_dir

if TYPE_CHECKING:
    from epitaph.core.engine import ScanEngine

logger = logging.getLogger("epitaph.execution.checkers.email.executor")


class EmailReconExecutor:
    """Оркестратор параллельной проверки eMail через Google и сервис-чекеры."""

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

        self.google_checker = GoogleAccountChecker()
        # Инициализация всех email-чекеров из реестра
        self.email_checkers = EmailCheckerRegistry.get_all_instances()

    async def run_search(
        self,
        target: TargetProfile,
        output_dir: Optional[Path] = None,
    ) -> ScanSessionResult:
        session_id = uuid.uuid4().hex[:8]
        start_time = datetime.now(timezone.utc)
        total_checks = 1 + len(self.email_checkers)

        await self.event_queue.put(StartScanEvent(target=target, session_id=session_id))
        await self.event_queue.put(
            LogEvent(
                message=f"Запуск глубокой разведки по eMail ({total_checks} сервисов): {target.username}...",
                level="INFO",
            )
        )

        completed_count = 0
        all_results: List[CheckResult] = []

        async def _run_single(checker_instance: Any) -> None:
            nonlocal completed_count
            res = await self.engine.scheduler.run_checker(checker_instance, target)
            all_results.append(res)
            completed_count += 1
            await self.event_queue.put(CheckResultEvent(result=res))
            await self.event_queue.put(
                ProgressUpdateEvent(completed=completed_count, total=total_checks)
            )

        # Параллельный запуск через asyncio.TaskGroup ядра
        async with asyncio.TaskGroup() as tg:
            tg.create_task(_run_single(self.google_checker))
            for checker in self.email_checkers:
                tg.create_task(_run_single(checker))

        session_result = ScanSessionResult(
            session_id=session_id,
            target=target,
            start_time=start_time,
            end_time=datetime.now(timezone.utc),
            results=all_results,
        )

        target_out = output_dir or get_default_report_dir(session_id, target.username)
        reports = await self.dispatcher.export_all(session_result, target_out)
        await self.event_queue.put(
            ScanCompletedEvent(session_id=session_id, report_paths=reports)
        )

        return session_result
