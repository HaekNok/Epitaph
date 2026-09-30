import time
from typing import Any, Optional
import httpx

from epitaph.execution.base import BasePlatformChecker
from epitaph.execution.checkers.google.auth import GoogleSessionCredentials
from epitaph.execution.checkers.google.models import GoogleAccountMetadata
from epitaph.execution.checkers.google.services.calendar import probe_calendar_timezone
from epitaph.execution.checkers.google.services.maps import extract_maps_activity
from epitaph.execution.checkers.google.services.people import lookup_people_data
from epitaph.execution.registry import register_checker
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.result import CheckResult
from epitaph.models.target import TargetProfile


@register_checker
class GoogleAccountChecker(BasePlatformChecker):
    def __init__(
        self,
        credentials: Optional[GoogleSessionCredentials] = None,
        rate_limit_delay: float = 2.0,
    ) -> None:
        self.credentials = credentials
        self._delay = rate_limit_delay

    @property
    def name(self) -> str:
        return "Google"

    @property
    def domain(self) -> str:
        return "google.com"

    @property
    def execution_type(self) -> ExecutionType:
        return ExecutionType.HTTP

    @property
    def rate_limit_delay(self) -> float:
        return self._delay

    async def check_browser(self, target: TargetProfile, context: Any) -> CheckResult:
        return CheckResult(
            platform_name=self.name,
            target=target,
            status=DetectionStatus.BLOCKED,
            execution_type=self.execution_type,
            error_message="Браузерная проверка Google не поддерживается.",
        )

    async def check_http(
        self,
        target: TargetProfile,
        client: httpx.AsyncClient,
    ) -> CheckResult:
        email = target.username if "@" in target.username else f"{target.username}@gmail.com"
        start_time = time.perf_counter()

        creds = self.credentials or GoogleSessionCredentials.load_from_storage()
        if creds is None:
            tz = await probe_calendar_timezone(email, client)
            elapsed = (time.perf_counter() - start_time) * 1000.0
            if tz:
                metadata = GoogleAccountMetadata(
                    gaia_id="",
                    email=email,
                    calendar_timezone=tz,
                )
                dump_fn = getattr(metadata, "model_dump", getattr(metadata, "dict", None))
                return CheckResult(
                    platform_name=self.name,
                    target=target,
                    status=DetectionStatus.FOUND,
                    profile_url=f"https://calendar.google.com/calendar/htmlembed?src={email}",
                    response_time_ms=elapsed,
                    execution_type=self.execution_type,
                    extracted_data=dump_fn(),
                )
            return CheckResult(
                platform_name=self.name,
                target=target,
                status=DetectionStatus.ERROR,
                execution_type=self.execution_type,
                response_time_ms=elapsed,
                error_message="Сессионные токены Google не сконфигурированы в ~/.epitaph/credentials/",
            )

        try:
            people_res = await lookup_people_data(email, creds, client)
            if people_res is None:
                elapsed = (time.perf_counter() - start_time) * 1000.0
                return CheckResult(
                    platform_name=self.name,
                    target=target,
                    status=DetectionStatus.NOT_FOUND,
                    execution_type=self.execution_type,
                    response_time_ms=elapsed,
                )

            gaia_id = people_res["gaia_id"]
            tz = await probe_calendar_timezone(email, client)
            maps_info = await extract_maps_activity(gaia_id, client)

            metadata = GoogleAccountMetadata(
                gaia_id=gaia_id,
                email=email,
                display_name=people_res.get("display_name"),
                avatar_url=people_res.get("avatar_url"),
                is_workspace_account=people_res.get("is_workspace", False),
                calendar_timezone=tz,
                maps_profile_url=f"https://www.google.com/maps/contrib/{gaia_id}",
                maps_reviews_count=len(maps_info),
                maps_locations=maps_info,
                youtube_channel_id=people_res.get("youtube_channel_id"),
            )

            dump_fn = getattr(metadata, "model_dump", getattr(metadata, "dict", None))
            elapsed = (time.perf_counter() - start_time) * 1000.0

            return CheckResult(
                platform_name=self.name,
                target=target,
                status=DetectionStatus.FOUND,
                execution_type=self.execution_type,
                profile_url=f"https://myaccount.google.com/?authuser={email}",
                response_time_ms=elapsed,
                extracted_data=dump_fn(),
            )

        except httpx.HTTPStatusError as err:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            code = err.response.status_code
            status = DetectionStatus.ERROR
            if code == 429:
                status = DetectionStatus.RATE_LIMITED
            elif code in (401, 403):
                status = DetectionStatus.BLOCKED

            return CheckResult(
                platform_name=self.name,
                target=target,
                status=status,
                execution_type=self.execution_type,
                response_time_ms=elapsed,
                http_status_code=code,
                error_message=f"Google API Error {code}: {err}",
            )
        except Exception as err:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return CheckResult(
                platform_name=self.name,
                target=target,
                status=DetectionStatus.ERROR,
                execution_type=self.execution_type,
                response_time_ms=elapsed,
                error_message=str(err),
            )
