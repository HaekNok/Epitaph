# Анализатор банковских карт и BIN-идентификаторов (Слот 10)
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
from epitaph.execution.checkers.bank_card.models import BankCardMetadata
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.result import CheckResult, ScanSessionResult
from epitaph.models.target import TargetProfile
from epitaph.reporting.dispatcher import ReportDispatcher, get_default_report_dir

if TYPE_CHECKING:
    from epitaph.core.engine import ScanEngine

logger = logging.getLogger("epitaph.execution.checkers.bank_card.executor")


class BankCardExecutor:
    # Исполнитель алгоритма Луна и детекции платежной системы
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

    def _check_luhn(self, card_digits: str) -> bool:
        # Проверка контрольной суммы по алгоритму Луна (Luhn mod 10)
        total = 0
        reversed_digits = card_digits[::-1]
        for idx, char in enumerate(reversed_digits):
            d = int(char)
            if idx % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        return total % 10 == 0

    def _detect_payment_system(self, digits: str) -> str:
        # Определение платежной сети по первым цифрам IIN/BIN
        if digits.startswith("4"):
            return "Visa"
        if digits.startswith(("51", "52", "53", "54", "55")) or (len(digits) >= 4 and 2221 <= int(digits[:4]) <= 2720):
            return "Mastercard"
        if digits.startswith("2"):
            return "MIR"
        if digits.startswith(("34", "37")):
            return "American Express"
        if digits.startswith("62"):
            return "UnionPay"
        return "Unknown Network"

    def _analyze_card(self, raw: str) -> BankCardMetadata:
        # Маскирование номера с сохранением BIN (первые 6) и хвоста (последние 4)
        digits = re.sub(r"\D+", "", raw)
        is_luhn = self._check_luhn(digits) if len(digits) >= 12 else False
        bin_part = digits[:6] if len(digits) >= 6 else digits
        system = self._detect_payment_system(digits) if digits else "Unknown"

        if len(digits) >= 10:
            masked = f"{digits[:4]} {digits[4:6]}** **** {digits[-4:]}"
        else:
            masked = digits

        return BankCardMetadata(
            masked_number=masked,
            bin_number=bin_part,
            payment_system=system,
            is_luhn_valid=is_luhn,
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
        meta = self._analyze_card(target.username)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        status = DetectionStatus.FOUND if meta.is_luhn_valid else DetectionStatus.ERROR
        res = CheckResult(
            platform_name="Bank Card / BIN Validator",
            target=target,
            status=status,
            response_time_ms=elapsed_ms,
            execution_type=ExecutionType.HTTP,
            extracted_data=meta.model_dump(),
            error_message=None if meta.is_luhn_valid else "Неверная контрольная сумма Луна",
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
