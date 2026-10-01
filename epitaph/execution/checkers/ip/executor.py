# Координатор сетевой геолокации и PTR-разведки IP-адресов (Слот 13)
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import ipaddress
import logging
from pathlib import Path
import socket
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
from epitaph.execution.checkers.ip.models import IpMetadata
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.result import CheckResult, ScanSessionResult
from epitaph.models.target import TargetProfile
from epitaph.reporting.dispatcher import ReportDispatcher, get_default_report_dir

if TYPE_CHECKING:
    from epitaph.core.engine import ScanEngine

logger = logging.getLogger("epitaph.execution.checkers.ip.executor")


class IpExecutor:
    # Исполнитель валидации IPv4/IPv6, обратного DNS и запроса ASN
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

    async def run_search(
        self,
        target: TargetProfile,
        output_dir: Optional[Path] = None,
    ) -> ScanSessionResult:
        session_id = uuid.uuid4().hex[:8]
        start_time = datetime.now(timezone.utc)
        await self.event_queue.put(StartScanEvent(target=target, session_id=session_id))

        t0 = time.perf_counter()
        raw_ip = target.username.strip()

        try:
            ip_obj = ipaddress.ip_address(raw_ip)
            is_priv = ip_obj.is_private or ip_obj.is_loopback
            version = ip_obj.version
        except ValueError:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            res = CheckResult(
                platform_name="IP Network Intelligence",
                target=target,
                status=DetectionStatus.ERROR,
                response_time_ms=elapsed_ms,
                execution_type=ExecutionType.HTTP,
                error_message="Некорректный синтаксис IPv4/IPv6 адреса",
            )
            results = [res]
            session_result = ScanSessionResult(
                session_id=session_id, target=target, start_time=start_time, end_time=datetime.now(timezone.utc), results=results
            )
            return session_result

        ptr = None
        try:
            ptr_res = await asyncio.to_thread(socket.gethostbyaddr, str(ip_obj))
            ptr = ptr_res[0] if ptr_res else None
        except Exception:
            pass

        country = None
        city = None
        asn = None
        org = None

        if not is_priv:
            client = await self.engine.scheduler.http_manager.get_client()
            try:
                resp = await client.get(f"https://ipapi.co/{ip_obj}/json/", timeout=5.0)
                if resp.status_code == 200:
                    d = resp.json()
                    country = d.get("country_name")
                    city = d.get("city")
                    asn = d.get("asn")
                    org = d.get("org")
            except Exception:
                pass

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        meta = IpMetadata(
            ip=str(ip_obj),
            ip_version=version,
            is_private=is_priv,
            is_bogon=is_priv,
            reverse_dns=ptr,
            country=country,
            city=city,
            asn=asn,
            org=org,
        )
        res = CheckResult(
            platform_name="IP Network Intelligence",
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
