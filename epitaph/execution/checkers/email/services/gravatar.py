"""Модуль проверки профиля Gravatar по email."""
from __future__ import annotations

import hashlib
import time
import httpx

from epitaph.execution.checkers.email.base import BaseEmailChecker
from epitaph.execution.checkers.email.registry import EmailCheckerRegistry
from epitaph.models.base import DetectionStatus
from epitaph.models.result import CheckResult
from epitaph.models.target import TargetProfile


@EmailCheckerRegistry.register("gravatar")
class GravatarEmailChecker(BaseEmailChecker):
    @property
    def name(self) -> str:
        return "Gravatar"

    async def probe_email(
        self,
        email: str,
        target: TargetProfile,
        client: httpx.AsyncClient,
        start_time: float,
    ) -> CheckResult:
        email_hash = hashlib.md5(email.encode("utf-8")).hexdigest()
        profile_url = f"https://en.gravatar.com/{email_hash}.json"
        avatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"

        headers = self.default_headers.copy()
        resp = await client.get(profile_url, headers=headers)
        elapsed_ms = (time.monotonic() - start_time) * 1000

        if resp.status_code == 200:
            extracted: dict[str, object] = {"avatar_url": avatar_url}
            try:
                entry = resp.json().get("entry", [{}])[0]
                if "displayName" in entry:
                    extracted["display_name"] = entry["displayName"]
                if "currentLocation" in entry:
                    extracted["location"] = entry["currentLocation"]
            except Exception:
                pass

            return self.create_result(
                target=target,
                status=DetectionStatus.FOUND,
                response_time_ms=elapsed_ms,
                http_status_code=200,
                profile_url=f"https://gravatar.com/{email_hash}",
                extracted_data=extracted,
            )

        if resp.status_code == 404:
            return self.create_result(
                target=target,
                status=DetectionStatus.NOT_FOUND,
                response_time_ms=elapsed_ms,
                http_status_code=404,
            )

        return self.create_result(
            target=target,
            status=DetectionStatus.ERROR,
            response_time_ms=elapsed_ms,
            http_status_code=resp.status_code,
            error_message="Ошибка запроса к Gravatar",
        )
