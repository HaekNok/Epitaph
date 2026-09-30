from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class GoogleMapReviewLocation(BaseModel):
    model_config = ConfigDict(frozen=True)

    place_name: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    rating: Optional[int] = Field(default=None, ge=1, le=5)
    review_timestamp: Optional[datetime] = None
    review_text: Optional[str] = None


class GoogleAccountMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)

    gaia_id: str
    email: str
    display_name: Optional[str] = None
    avatar_url: Optional[str] = None
    is_workspace_account: bool = False
    calendar_timezone: Optional[str] = None
    maps_profile_url: Optional[str] = None
    maps_reviews_count: int = 0
    maps_locations: List[GoogleMapReviewLocation] = Field(default_factory=list)
    youtube_channel_id: Optional[str] = None
    raw_services_data: Dict[str, Any] = Field(default_factory=dict)
