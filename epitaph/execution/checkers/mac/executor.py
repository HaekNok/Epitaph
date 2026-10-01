# Анализатор и верификатор аппаратных MAC-адресов IEEE OUI (Слот 16)
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
from pathlib import Path
import re
import time
from typing import TYPE_CHECKING, Any, Optional
import uuid

import httpx

from epitaph.core.events import (
    CheckResultEvent,
    LogEvent,
    ProgressUpdateEvent,
    ScanCompletedEvent,
    StartScanEvent,
)
from epitaph.execution.checkers.mac.models import MacMetadata
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.result import CheckResult, ScanSessionResult
from epitaph.models.target import TargetProfile
from epitaph.reporting.dispatcher import ReportDispatcher, get_default_report_dir

if TYPE_CHECKING:
    from epitaph.core.engine import ScanEngine

logger = logging.getLogger("epitaph.execution.checkers.mac.executor")


class MacExecutor:
    # Исполнитель нормализации EUI-48 и запроса вендора сетевой карты
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

    def _normalize(self, raw: str) -> Optional[tuple[str, str, bool, bool]]:
        # Нормализация MAC к стандартному двоеточию и определение битовых флагов
        clean = re.sub(r"[^a-fA-F0-9]", "", raw)
        if len(clean) != 12:
            return None
        formatted = ":".join(clean[i:i+2].upper() for i in range(0, 12, 2))
        oui = formatted[:8]

        first_byte = int(clean[:2], 16)
        is_multicast = bool(first_byte & 1)
        is_local = bool(first_byte & 2)
        return (formatted, oui, is_multicast, is_local)

    async def run_search(
        self,
        target: TargetProfile,
        output_dir: Optional[Path] = None,
    ) -> ScanSessionResult:
        session_id = uuid.uuid4().hex[:8]
        start_time = datetime.now(timezone.utc)
        await self.event_queue.put(StartScanEvent(target=target, session_id=session_id))

        t0 = time.perf_counter()
        parsed = self._normalize(target.username)

        if parsed is None:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            res = CheckResult(
                platform_name="MAC OUI Registry",
                target=target,
                status=DetectionStatus.ERROR,
                response_time_ms=elapsed_ms,
                execution_type=ExecutionType.HTTP,
                error_message="Некорректный синтаксис MAC-адреса (требуется 12 hex-символов)",
            )
            results = [res]
            session_result = ScanSessionResult(
                session_id=session_id, target=target, start_time=start_time, end_time=datetime.now(timezone.utc), results=results
            )
            return session_result

        norm_mac, oui, is_multi, is_local = parsed
        vendor = None

        client = await self.engine.scheduler.http_manager.get_client()
        try:
            resp = await client.get(f"https://api.macvendors.com/{norm_mac}", timeout=4.0)
            if resp.status_code == 200:
                vendor = resp.text.strip()
        except Exception:
            pass

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        meta = MacMetadata(
            raw_mac=target.username,
            normalized_mac=norm_mac,
            oui_prefix=oui,
            vendor=vendor,
            is_multicast=is_multi,
            is_locally_administered=is_local,
            is_valid=True,
        )

        res = CheckResult(
            platform_name="MAC OUI Registry",
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
