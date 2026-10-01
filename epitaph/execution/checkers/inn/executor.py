# Валидатор и поисковый координатор по ИНН (Слот 6)
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
from epitaph.execution.checkers.inn.models import InnMetadata
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.result import CheckResult, ScanSessionResult
from epitaph.models.target import TargetProfile
from epitaph.reporting.dispatcher import ReportDispatcher, get_default_report_dir

if TYPE_CHECKING:
    from epitaph.core.engine import ScanEngine

logger = logging.getLogger("epitaph.execution.checkers.inn.executor")


class InnExecutor:
    # Исполнитель математической верификации ИНН 10 и 12 цифр
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

    def _validate_inn(self, raw_inn: str) -> InnMetadata:
        # Проверка контрольных разрядов ИНН юрлиц (10 цифр) и физлиц (12 цифр)
        inn = re.sub(r"\D+", "", raw_inn)
        if len(inn) == 10:
            coeffs = [2, 4, 10, 3, 5, 9, 4, 6, 8]
            ctrl = sum(int(inn[i]) * coeffs[i] for i in range(9)) % 11 % 10
            is_valid = ctrl == int(inn[9])
            return InnMetadata(
                inn=inn,
                inn_type="Юридическое лицо (10 знаков)",
                is_valid=is_valid,
                region_code=inn[:2],
                checksum_valid=is_valid,
            )
        if len(inn) == 12:
            c1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
            c2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
            ctrl1 = sum(int(inn[i]) * c1[i] for i in range(10)) % 11 % 10
            ctrl2 = sum(int(inn[i]) * c2[i] for i in range(11)) % 11 % 10
            is_valid = (ctrl1 == int(inn[10])) and (ctrl2 == int(inn[11]))
            return InnMetadata(
                inn=inn,
                inn_type="Физическое лицо / ИП (12 знаков)",
                is_valid=is_valid,
                region_code=inn[:2],
                checksum_valid=is_valid,
            )
        return InnMetadata(
            inn=inn,
            inn_type="Некорректная разрядность",
            is_valid=False,
            region_code=None,
            checksum_valid=False,
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
        meta = self._validate_inn(target.username)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        status = DetectionStatus.FOUND if meta.is_valid else DetectionStatus.ERROR
        res = CheckResult(
            platform_name="FNS INN Validator",
            target=target,
            status=status,
            response_time_ms=elapsed_ms,
            execution_type=ExecutionType.HTTP,
            extracted_data=meta.model_dump(),
            error_message=None if meta.is_valid else "Неверная контрольная сумма или длина ИНН",
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
