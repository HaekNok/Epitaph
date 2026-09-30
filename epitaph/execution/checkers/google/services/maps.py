import logging
from typing import List
import httpx
from epitaph.execution.checkers.google.models import GoogleMapReviewLocation

logger = logging.getLogger("epitaph.execution.checkers.google.maps")


async def extract_maps_activity(gaia_id: str, client: httpx.AsyncClient) -> List[GoogleMapReviewLocation]:
    url = f"https://www.google.com/maps/contrib/{gaia_id}"
    try:
        await client.get(url, follow_redirects=True)
    except Exception as err:
        logger.debug("Сбой получения данных карт для Gaia ID %s: %s", gaia_id, err)
    return []
