import logging
from typing import Any, Dict, Optional
from urllib.parse import quote
import httpx
from epitaph.execution.checkers.google.auth import GoogleSessionCredentials

logger = logging.getLogger("epitaph.execution.checkers.google.people")


async def lookup_people_data(
    email: str,
    credentials: GoogleSessionCredentials,
    client: httpx.AsyncClient,
) -> Optional[Dict[str, Any]]:
    url = (
        f"https://people-pa.clients6.google.com/v2/peopleBatchGet"
        f"?personId={quote(email, safe='')}"
        f"&readMask=names,photos,emailAddresses,metadata,urls"
        f"&sources=READ_SOURCE_TYPE_CONTACT,READ_SOURCE_TYPE_PROFILE"
    )
    headers = credentials.build_headers()

    res = await client.get(url, headers=headers)
    if res.status_code == 404:
        return None
    if res.status_code in (401, 403, 429):
        res.raise_for_status()
    if res.status_code != 200:
        return None

    try:
        person = res.json().get("responses", [{}])[0].get("person")
    except Exception:
        return None

    if not person:
        return None

    gaia_id = next(
        (str(s["id"]) for s in person.get("metadata", {}).get("sources", []) if str(s.get("id", "")).isdigit()),
        None,
    )
    if not gaia_id:
        return None

    names = person.get("names")
    display_name = names[0].get("displayName") if names else None

    photos = person.get("photos")
    avatar_url = photos[0].get("url") if photos else None

    domain = email.split("@")[-1].lower() if "@" in email else ""
    is_workspace = domain not in ("gmail.com", "googlemail.com", "")

    youtube_channel_id = next(
        (
            u["value"].split("youtube.com/channel/")[1].split("/")[0]
            for u in person.get("urls", [])
            if "youtube.com/channel/" in u.get("value", "")
        ),
        None,
    )

    return {
        "gaia_id": gaia_id,
        "email": email,
        "display_name": display_name,
        "avatar_url": avatar_url,
        "is_workspace": is_workspace,
        "youtube_channel_id": youtube_channel_id,
        "raw": person,
    }
