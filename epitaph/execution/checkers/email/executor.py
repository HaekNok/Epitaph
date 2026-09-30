"""Координатор сканирования по email для Слота 2 с защитой OPSEC Fail-Closed и Passive Mode."""
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
from epitaph.models.base import DetectionStatus
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
        passive_mode: bool = True,
    ) -> None:
        self.event_queue = event_queue or asyncio.Queue()
        self.dispatcher = dispatcher or ReportDispatcher()
        self.passive_mode = passive_mode
        if engine is None:
            from epitaph.core.engine import ScanEngine
            self.engine = ScanEngine(event_queue=self.event_queue, dispatcher=self.dispatcher)
        else:
            self.engine = engine

        self.google_checker = GoogleAccountChecker()

    async def run_search(
        self,
        target: TargetProfile,
        output_dir: Optional[Path] = None,
    ) -> ScanSessionResult:
        # Нормализация email-адреса цели
        raw_email = target.username.strip().lower()
        if "@" not in raw_email:
            raw_email = f"{raw_email}@gmail.com"
        target = TargetProfile(username=raw_email, metadata=target.metadata)

        # OPSEC-03: Проверка готовности прокси-пула перед запуском конкурентных задач
        if getattr(self.engine.scheduler, "enforce_proxy", False):
            pm = getattr(self.engine.scheduler, "proxy_manager", None)
            if pm is not None and hasattr(pm, "has_available_proxies"):
                if not await pm.has_available_proxies():
                    raise RuntimeError("OPSEC Fail-Closed: Пул прокси истощен при enforce_proxy. Сканирование eMail заблокировано.")

        # Загрузка актуальных инстансов чекеров из реестра
        email_checkers = EmailCheckerRegistry.get_all_instances()

        # OPSEC-02: Фильтрация активных триггерных чекеров в пассивном режиме (защита от target tipping-off)
        active_checkers = []
        for checker in email_checkers:
            if self.passive_mode and getattr(checker, "is_active_probe", False):
                await self.event_queue.put(
                    LogEvent(
                        message=f"[ OPSEC Passive ] Пропуск активного чекера {checker.name} (риск уведомления цели)",
                        level="DEBUG",
                    )
                )
                continue
            active_checkers.append(checker)

        session_id = uuid.uuid4().hex[:8]
        start_time = datetime.now(timezone.utc)
        total_checks = 1 + len(active_checkers)

        await self.event_queue.put(StartScanEvent(target=target, session_id=session_id))
        mode_desc = "пассивный" if self.passive_mode else "полный"
        await self.event_queue.put(
            LogEvent(
                message=f"Запуск разведки по eMail ({mode_desc} режим, {total_checks} модулей): {target.username}...",
                level="INFO",
            )
        )

        completed_count = 0
        all_results: List[CheckResult] = []

        async def _run_single(checker_instance: Any) -> None:
            nonlocal completed_count
            try:
                res = await self.engine.scheduler.run_checker(checker_instance, target)
            except Exception as exc:
                res = CheckResult(
                    platform_name=getattr(checker_instance, "name", "Unknown"),
                    target=target,
                    status=DetectionStatus.ERROR,
                    response_time_ms=0.0,
                    error_message=f"Сбой выполнения чекера: {exc}",
                )
            all_results.append(res)
            completed_count += 1
            await self.event_queue.put(CheckResultEvent(result=res))
            await self.event_queue.put(
                ProgressUpdateEvent(completed=completed_count, total=total_checks)
            )

        async with asyncio.TaskGroup() as tg:
            tg.create_task(_run_single(self.google_checker))
            for checker in active_checkers:
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
