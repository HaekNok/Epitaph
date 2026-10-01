# Асинхронный координатор поиска поддоменов через Certificate Transparency (Слот 14)
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re
import time
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import quote
import uuid

import httpx

from epitaph.core.events import (
    CheckResultEvent,
    LogEvent,
    ProgressUpdateEvent,
    ScanCompletedEvent,
    StartScanEvent,
)
from epitaph.execution.checkers.subdomain.models import SubdomainMetadata
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.result import CheckResult, ScanSessionResult
from epitaph.models.target import TargetProfile
from epitaph.reporting.dispatcher import ReportDispatcher, get_default_report_dir

if TYPE_CHECKING:
    from epitaph.core.engine import ScanEngine

logger = logging.getLogger("epitaph.execution.checkers.subdomain.executor")


class SubdomainExecutor:
    # Исполнитель запроса логов crt.sh и нормализации доменных имен
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

    def _clean_domain(self, raw: str) -> str:
        # Очистка протоколов и слешей из целевого доменного имени
        d = raw.strip().lower()
        d = re.sub(r"^https?://", "", d)
        d = d.split("/")[0].strip()
        return d

    async def run_search(
        self,
        target: TargetProfile,
        output_dir: Optional[Path] = None,
    ) -> ScanSessionResult:
        session_id = uuid.uuid4().hex[:8]
        start_time = datetime.now(timezone.utc)
        await self.event_queue.put(StartScanEvent(target=target, session_id=session_id))

        domain = self._clean_domain(target.username)
        await self.event_queue.put(
            LogEvent(message=f"Поиск поддоменов для '{domain}' через crt.sh...", level="INFO")
        )

        t0 = time.perf_counter()
        subs: set[str] = set()
        client = await self.engine.scheduler.http_manager.get_client()

        api_url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
        try:
            resp = await client.get(api_url, timeout=15.0)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name_val = entry.get("name_value", "")
                    for sub in name_val.split("\n"):
                        sub_clean = sub.strip().lower()
                        if sub_clean and not sub_clean.startswith("*."):
                            subs.add(sub_clean)

            sub_list = sorted(list(subs))
            meta = SubdomainMetadata(
                domain=domain,
                subdomains_count=len(sub_list),
                subdomains=sub_list[:100],
            )
            status = DetectionStatus.FOUND if sub_list else DetectionStatus.NOT_FOUND
            res = CheckResult(
                platform_name="Certificate Transparency (crt.sh)",
                target=target,
                status=status,
                response_time_ms=elapsed_ms,
                execution_type=ExecutionType.HTTP,
                http_status_code=resp.status_code,
                extracted_data=meta.model_dump(),
            )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            res = CheckResult(
                platform_name="Certificate Transparency (crt.sh)",
                target=target,
                status=DetectionStatus.ERROR,
                response_time_ms=elapsed_ms,
                execution_type=ExecutionType.HTTP,
                error_message=f"Сбой выборки поддоменов: {exc}",
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
