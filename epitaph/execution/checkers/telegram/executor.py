# Координатор OSINT-разведки профилей и каналов Telegram (Слот 2)
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
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
from epitaph.execution.checkers.telegram.models import TelegramProfileMetadata
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.result import CheckResult, ScanSessionResult
from epitaph.models.target import TargetProfile
from epitaph.reporting.dispatcher import ReportDispatcher, get_default_report_dir

if TYPE_CHECKING:
    from epitaph.core.engine import ScanEngine

logger = logging.getLogger("epitaph.execution.checkers.telegram.executor")


class TelegramExecutor:
    # Исполнитель поиска публичных метаданных Telegram
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

    def _clean_target(self, raw_val: str) -> str:
        # Очистка юзернейма от символов собаки и ссылок t.me
        cleaned = raw_val.strip()
        cleaned = re.sub(r"^https?://t\.me/", "", cleaned)
        cleaned = cleaned.lstrip("@").strip()
        return cleaned

    async def run_search(
        self,
        target: TargetProfile,
        output_dir: Optional[Path] = None,
    ) -> ScanSessionResult:
        session_id = uuid.uuid4().hex[:8]
        start_time = datetime.now(timezone.utc)
        clean_name = self._clean_target(target.username)
        await self.event_queue.put(StartScanEvent(target=target, session_id=session_id))
        await self.event_queue.put(
            LogEvent(message=f"Запуск разведки Telegram для @{clean_name}...", level="INFO")
        )

        results: list[CheckResult] = []
        probe_start = time.perf_counter()
        preview_url = f"https://t.me/{quote(clean_name)}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

        client = await self.engine.scheduler.http_manager.get_client()
        try:
            resp = await client.get(preview_url, headers=headers, follow_redirects=True)
            elapsed_ms = (time.perf_counter() - probe_start) * 1000.0
            html = resp.text

            if resp.status_code == 200 and "tgme_page_title" in html:
                title_match = re.search(r'<div class="tgme_page_title"[^>]*><span dir="auto">([^<]+)</span>', html)
                title = title_match.group(1).strip() if title_match else None
                bio_match = re.search(r'<div class="tgme_page_description[^"]*"[^>]*>(.*?)</div>', html, re.DOTALL)
                bio = re.sub(r"<[^>]+>", "", bio_match.group(1)).strip() if bio_match else None
                photo_match = re.search(r'<img class="tgme_page_photo_image" src="([^"]+)"', html)
                avatar = photo_match.group(1) if photo_match else None
                is_channel = "tgme_channel_info" in html or "subscribers" in html
                is_bot = "tgme_page_extra" in html and "bot" in html.lower()

                meta = TelegramProfileMetadata(
                    target_query=target.username,
                    username=clean_name,
                    title=title,
                    bio=bio,
                    avatar_url=avatar,
                    is_channel=is_channel,
                    is_bot=is_bot,
                )
                res = CheckResult(
                    platform_name="Telegram Web",
                    target=target,
                    status=DetectionStatus.FOUND,
                    profile_url=preview_url,
                    response_time_ms=elapsed_ms,
                    execution_type=ExecutionType.HTTP,
                    http_status_code=resp.status_code,
                    extracted_data=meta.model_dump(),
                )
            else:
                res = CheckResult(
                    platform_name="Telegram Web",
                    target=target,
                    status=DetectionStatus.NOT_FOUND,
                    response_time_ms=elapsed_ms,
                    execution_type=ExecutionType.HTTP,
                    http_status_code=resp.status_code,
                )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - probe_start) * 1000.0
            res = CheckResult(
                platform_name="Telegram Web",
                target=target,
                status=DetectionStatus.ERROR,
                response_time_ms=elapsed_ms,
                execution_type=ExecutionType.HTTP,
                error_message=str(exc),
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
