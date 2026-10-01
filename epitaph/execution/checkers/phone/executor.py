# Координатор анализа телефонных номеров E.164 (Слот 4)
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
from pathlib import Path
import re
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
from epitaph.execution.checkers.phone.models import PhoneMetadata
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.result import CheckResult, ScanSessionResult
from epitaph.models.target import TargetProfile
from epitaph.reporting.dispatcher import ReportDispatcher, get_default_report_dir

if TYPE_CHECKING:
    from epitaph.core.engine import ScanEngine

logger = logging.getLogger("epitaph.execution.checkers.phone.executor")


class PhoneExecutor:
    # Исполнитель парсинга и валидации телефонии
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

    def _sanitize(self, raw: str) -> str:
        # Нормализация телефонного номера к международному формату цифр
        digits = re.sub(r"\D+", "", raw)
        if raw.startswith("+"):
            return f"+{digits}"
        if len(digits) == 10 and digits.startswith("9"):
            return f"+7{digits}"
        if len(digits) == 11 and digits.startswith("8"):
            return f"+7{digits[1:]}"
        return f"+{digits}" if digits else ""

    def _detect_country(self, e164: str) -> tuple[str, str, str]:
        # Детекция страны и мобильного оператора по телефонному префиксу
        if e164.startswith("+380"):
            return ("Украина", "+380", "Kyivstar / Vodafone / lifecell")
        if e164.startswith("+7"):
            return ("Казахстан / РФ", "+7", "MTS / Beeline / MegaFon / Tele2")
        if e164.startswith("+1"):
            return ("США / Канада", "+1", "North American Numbering Plan")
        if e164.startswith("+44"):
            return ("Великобритания", "+44", "UK Telephony")
        if e164.startswith("+49"):
            return ("Германия", "+49", "Deutsche Telekom / Vodafone")
        if e164.startswith("+48"):
            return ("Польша", "+48", "Orange / Play / Plus / T-Mobile")
        return ("Международный", e164[:3], "Unknown Carrier")

    async def run_search(
        self,
        target: TargetProfile,
        output_dir: Optional[Path] = None,
    ) -> ScanSessionResult:
        session_id = uuid.uuid4().hex[:8]
        start_time = datetime.now(timezone.utc)
        await self.event_queue.put(StartScanEvent(target=target, session_id=session_id))

        cleaned = self._sanitize(target.username)
        await self.event_queue.put(
            LogEvent(message=f"Нормализация телефона: {target.username} -> {cleaned}", level="INFO")
        )

        results: list[CheckResult] = []
        t0 = time.perf_counter()

        if len(cleaned) < 8 or len(cleaned) > 16:
            res = CheckResult(
                platform_name="Phone Parser",
                target=target,
                status=DetectionStatus.ERROR,
                response_time_ms=(time.perf_counter() - t0) * 1000.0,
                execution_type=ExecutionType.HTTP,
                error_message="Некорректная длина телефонного номера E.164",
            )
        else:
            country, code, carrier = self._detect_country(cleaned)
            meta = PhoneMetadata(
                raw_phone=target.username,
                cleaned_e164=cleaned,
                country=country,
                country_code=code,
                operator_name=carrier,
                whatsapp_url=f"https://wa.me/{cleaned.lstrip('+')}",
                telegram_url=f"https://t.me/{cleaned}",
                viber_url=f"viber://chat?number={cleaned.lstrip('+')}",
            )
            res = CheckResult(
                platform_name="Phone Parser",
                target=target,
                status=DetectionStatus.FOUND,
                response_time_ms=(time.perf_counter() - t0) * 1000.0,
                execution_type=ExecutionType.HTTP,
                extracted_data=meta.model_dump(),
                profile_url=meta.whatsapp_url,
            )

        results.append(res)
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
