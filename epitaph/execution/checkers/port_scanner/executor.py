# Асинхронный неблокирующий сканер TCP-портов (Слот 15)
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
from pathlib import Path
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
from epitaph.execution.checkers.port_scanner.models import PortScanMetadata
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.result import CheckResult, ScanSessionResult
from epitaph.models.target import TargetProfile
from epitaph.reporting.dispatcher import ReportDispatcher, get_default_report_dir

if TYPE_CHECKING:
    from epitaph.core.engine import ScanEngine

logger = logging.getLogger("epitaph.execution.checkers.port_scanner.executor")

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]


class PortScannerExecutor:
    # Исполнитель асинхронного сканирования портов через сокеты asyncio
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

    async def _probe_port(self, host: str, port: int, timeout: float = 1.5) -> tuple[int, bool, Optional[str]]:
        # Попытка асинхронного TCP-соединения с захватом заголовка
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            banner = None
            try:
                data = await asyncio.wait_for(reader.read(128), timeout=0.5)
                banner = data.decode("utf-8", errors="replace").strip()
            except Exception:
                pass
            writer.close()
            await writer.wait_closed()
            return (port, True, banner)
        except Exception:
            return (port, False, None)

    async def run_search(
        self,
        target: TargetProfile,
        output_dir: Optional[Path] = None,
    ) -> ScanSessionResult:
        session_id = uuid.uuid4().hex[:8]
        start_time = datetime.now(timezone.utc)
        await self.event_queue.put(StartScanEvent(target=target, session_id=session_id))

        host = target.username.strip().split(":")[0]
        await self.event_queue.put(
            LogEvent(message=f"Сканирование топ-{len(COMMON_PORTS)} TCP-портов на {host}...", level="INFO")
        )

        t0 = time.perf_counter()
        open_ports: list[int] = []
        banners: dict[int, str] = {}

        tasks = [self._probe_port(host, p) for p in COMMON_PORTS]
        results_raw = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results_raw:
            if isinstance(res, tuple) and res[1]:
                p, is_open, b = res
                open_ports.append(p)
                if b:
                    banners[p] = b

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        meta = PortScanMetadata(
            host=host,
            scanned_ports_count=len(COMMON_PORTS),
            open_ports=open_ports,
            banners=banners,
        )

        status = DetectionStatus.FOUND if open_ports else DetectionStatus.NOT_FOUND
        res = CheckResult(
            platform_name="TCP Port Scanner",
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
