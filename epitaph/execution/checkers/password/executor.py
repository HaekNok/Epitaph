# Координатор безопасного k-Anonymity аудита паролей (Слот 11)
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import logging
import math
from pathlib import Path
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
from epitaph.execution.checkers.password.models import PasswordBreachMetadata
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.result import CheckResult, ScanSessionResult
from epitaph.models.target import TargetProfile
from epitaph.reporting.dispatcher import ReportDispatcher, get_default_report_dir

if TYPE_CHECKING:
    from epitaph.core.engine import ScanEngine

logger = logging.getLogger("epitaph.execution.checkers.password.executor")


class PasswordExecutor:
    # Исполнитель zero-leakage проверки паролей через SHA-1 k-Anonymity
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

    def _calculate_entropy(self, pwd: str) -> float:
        # Расчет энтропии пароля по формуле Шеннона
        if not pwd:
            return 0.0
        charset_size = 0
        if any(c.islower() for c in pwd):
            charset_size += 26
        if any(c.isupper() for c in pwd):
            charset_size += 26
        if any(c.isdigit() for c in pwd):
            charset_size += 10
        if any(not c.isalnum() for c in pwd):
            charset_size += 33
        return len(pwd) * math.log2(max(charset_size, 2))

    async def run_search(
        self,
        target: TargetProfile,
        output_dir: Optional[Path] = None,
    ) -> ScanSessionResult:
        session_id = uuid.uuid4().hex[:8]
        start_time = datetime.now(timezone.utc)
        await self.event_queue.put(StartScanEvent(target=target, session_id=session_id))

        pwd = target.username
        sha1_hash = hashlib.sha1(pwd.encode("utf-8")).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        await self.event_queue.put(
            LogEvent(message=f"k-Anonymity SHA-1 префикс: {prefix} (пароль изолирован)", level="INFO")
        )

        t0 = time.perf_counter()
        entropy = self._calculate_entropy(pwd)
        strength = "СЛАБЫЙ" if entropy < 40 else ("СРЕДНИЙ" if entropy < 65 else "НАДЕЖНЫЙ")

        breach_count = 0
        is_compromised = False
        api_url = f"https://api.pwnedpasswords.com/range/{prefix}"
        client = await self.engine.scheduler.http_manager.get_client()

        try:
            resp = await client.get(api_url, timeout=10.0)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    parts = line.split(":")
                    if len(parts) == 2 and parts[0].strip() == suffix:
                        breach_count = int(parts[1].strip())
                        is_compromised = True
                        break

            meta = PasswordBreachMetadata(
                hash_prefix=prefix,
                is_compromised=is_compromised,
                breach_count=breach_count,
                entropy_bits=round(entropy, 1),
                strength_rating=strength,
            )
            status = DetectionStatus.FOUND if is_compromised else DetectionStatus.NOT_FOUND
            res = CheckResult(
                platform_name="HaveIBeenPwned Passwords",
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
                platform_name="HaveIBeenPwned Passwords",
                target=target,
                status=DetectionStatus.ERROR,
                response_time_ms=elapsed_ms,
                execution_type=ExecutionType.HTTP,
                error_message=f"Сетевой сбой API утечек: {exc}",
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
