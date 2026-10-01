# Анализатор и аудитор безопасности сессионных куки (Слот 12)
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
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
from epitaph.execution.checkers.cookies.models import CookieAuditMetadata
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.result import CheckResult, ScanSessionResult
from epitaph.models.target import TargetProfile
from epitaph.reporting.dispatcher import ReportDispatcher, get_default_report_dir

if TYPE_CHECKING:
    from epitaph.core.engine import ScanEngine

logger = logging.getLogger("epitaph.execution.checkers.cookies.executor")


class CookieExecutor:
    # Исполнитель разбора и аудита флагов Secure, HttpOnly, SameSite
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

    def _audit_cookies(self, raw_data: str) -> CookieAuditMetadata:
        # Аудит безопасности параметров сессионных файлов куки
        parsed: list[dict[str, Any]] = []
        try:
            items = json.loads(raw_data)
            if isinstance(items, list):
                parsed = items
            elif isinstance(items, dict):
                parsed = [items]
        except Exception:
            for line in raw_data.splitlines():
                parts = line.strip().split("\t")
                if len(parts) >= 7:
                    parsed.append({
                        "domain": parts[0],
                        "path": parts[2],
                        "secure": parts[3].lower() == "true",
                        "expires": parts[4],
                        "name": parts[5],
                        "value": parts[6],
                    })

        total = len(parsed)
        secure_cnt = sum(1 for c in parsed if c.get("secure") or c.get("secure") is True)
        httponly_cnt = sum(1 for c in parsed if c.get("httpOnly") or c.get("httponly"))
        samesite_cnt = sum(1 for c in parsed if str(c.get("sameSite", "")).lower() == "strict")

        risk = "HIGH" if (total > 0 and secure_cnt == 0) else ("MEDIUM" if httponly_cnt < total else "LOW")
        return CookieAuditMetadata(
            total_parsed=total,
            secure_count=secure_cnt,
            httponly_count=httponly_cnt,
            samesite_strict_count=samesite_cnt,
            risk_level=risk,
            cookies_list=parsed[:50],
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
        meta = self._audit_cookies(target.username)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        status = DetectionStatus.FOUND if meta.total_parsed > 0 else DetectionStatus.ERROR
        res = CheckResult(
            platform_name="Cookie Security Auditor",
            target=target,
            status=status,
            response_time_ms=elapsed_ms,
            execution_type=ExecutionType.HTTP,
            extracted_data=meta.model_dump(),
            error_message=None if meta.total_parsed > 0 else "Строка или файл куки не содержат распознаваемых записей",
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
