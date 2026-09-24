# Модуль интеграции инструмента Maigret для асинхронного поиска профилей по никнейму
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
    # Асинхронный координатор поиска по никнеймам на базе Maigret и ScanEngine

    def __init__(
        self,
        event_queue: Optional[asyncio.Queue[Any]] = None,
        engine: Optional[ScanEngine] = None,
        dispatcher: Optional[ReportDispatcher] = None,
    ) -> None:
        self.event_queue: asyncio.Queue[Any] = event_queue or asyncio.Queue()
        self.dispatcher = dispatcher or ReportDispatcher()
        if engine is None:
            from epitaph.core.engine import ScanEngine
            self.engine = ScanEngine(
                event_queue=self.event_queue, dispatcher=self.dispatcher
            )
        else:
            self.engine = engine

    async def run_search(
        self,
        target: TargetProfile,
        output_dir: Optional[Path] = None,
    ) -> ScanSessionResult:
        # Запуск асинхронного поиска по никнейму с потоковой отправкой событий
        session_id = uuid.uuid4().hex[:8]
        start_time = datetime.now(timezone.utc)
        await self.event_queue.put(
            StartScanEvent(target=target, session_id=session_id)
        )

        if HAS_MAIGRET and maigret is not None:
            try:
                return await self._run_native_maigret(
                    target, session_id, start_time, output_dir
                )
            except Exception as exc:
                logger.warning(
                    "Сбой нативного поиска Maigret: %s. Переключение на ScanEngine.", exc
                )
                await self.event_queue.put(
                    LogEvent(
                        message=f"Ошибка Maigret: {exc}. Переключение на встроенный движок.",
                        level="WARNING",
                    )
                )

        # Выполнение сканирования через встроенный асинхронный движок
        return await self.engine.run_scan(target, output_dir=output_dir)

    async def _run_native_maigret(
        self,
        target: TargetProfile,
        session_id: str,
        start_time: datetime,
        output_dir: Optional[Path],
    ) -> ScanSessionResult:
        # Выполнение поиска средствами библиотеки Maigret в изолированном пуле
        await self.event_queue.put(
            LogEvent(message=f"Запуск Maigret сканирования для {target.username}.")
        )

        def _execute_sync_search() -> List[Dict[str, Any]]:
            if hasattr(maigret, "search"):
                raw_results = maigret.search(username=target.username)
                return list(raw_results) if raw_results else []
            return []

        raw_items = await asyncio.to_thread(_execute_sync_search)
        results: List[CheckResult] = []
        total = max(len(raw_items), 1)

        for idx, item in enumerate(raw_items, start=1):
            status_str = str(item.get("status", "FOUND")).upper()
            status = DetectionStatus.FOUND if "FOUND" in status_str else DetectionStatus.NOT_FOUND
            res = CheckResult(
                platform_name=str(item.get("site_name", "Unknown")),
                target=target,
                status=status,
                profile_url=item.get("url_user"),
                response_time_ms=float(item.get("response_time", 0.0) or 0.0),
                execution_type=ExecutionType.HTTP,
                http_status_code=item.get("http_status"),
            )
            results.append(res)
            await self.event_queue.put(CheckResultEvent(result=res))
            await self.event_queue.put(
                ProgressUpdateEvent(completed=idx, total=total)
            )

        end_time = datetime.now(timezone.utc)
        session_result = ScanSessionResult(
            session_id=session_id,
            target=target,
            start_time=start_time,
            end_time=end_time,
            results=results,
        )

        target_out_dir = output_dir or get_default_report_dir(
            session_id, target.username
        )
        generated_reports = await self.dispatcher.export_all(
            session_result, target_out_dir
        )
        await self.event_queue.put(
            ScanCompletedEvent(
                session_id=session_id, report_paths=generated_reports
            )
        )

        return session_result
