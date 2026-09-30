import re
from typing import Optional
from urllib.parse import quote
import httpx

_TZ_PATTERN = re.compile(r'["\']?timeZone["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-/]+)["\']')


async def probe_calendar_timezone(email: str, client: httpx.AsyncClient) -> Optional[str]:
    url = f"https://calendar.google.com/calendar/htmlembed?src={quote(email, safe='')}"
    try:
        res = await client.get(url, follow_redirects=True)
        if res.status_code == 200:
            match = _TZ_PATTERN.search(res.text)
            if match:
                return match.group(1)
    except Exception:
        return None
    return None
