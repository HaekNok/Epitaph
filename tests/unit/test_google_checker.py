import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
from unittest.mock import AsyncMock, MagicMock
import httpx

from epitaph.execution.checkers.google.auth import GoogleSessionCredentials
from epitaph.execution.checkers.google.checker import GoogleAccountChecker
from epitaph.execution.checkers.google.models import GoogleAccountMetadata
from epitaph.execution.checkers.google.services.people import lookup_people_data
from epitaph.execution.checkers.google.services.calendar import probe_calendar_timezone
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.target import TargetProfile


def test_sapisid_hash_generation() -> None:
    # Проверка корректности расчета подписи SAPISIDHASH
    creds = GoogleSessionCredentials(sapisid="test_sapisid_val_123")
    header_val = creds.generate_sapisid_hash("https://contacts.google.com")
    assert header_val.startswith("SAPISIDHASH ")
    parts = header_val.replace("SAPISIDHASH ", "").split("_")
    assert len(parts) == 2
    assert parts[0].isdigit()
    assert len(parts[1]) == 40  # SHA-1 hex digest


def test_credentials_storage() -> None:
    # Проверка сохранения и загрузки учетных данных в защищенный файл 0600
    with tempfile.TemporaryDirectory() as td:
        cfg = Path(td) / "creds.json"
        creds = GoogleSessionCredentials(
            sapisid="sap123",
            sid="sid456",
            ssid="ssid789",
            hsid="hsid000",
        )
        saved = creds.save_to_storage(cfg)
        assert saved.is_file()
        loaded = GoogleSessionCredentials.load_from_storage(cfg)
        assert loaded is not None
        assert loaded.sapisid == "sap123"
        assert loaded.sid == "sid456"


async def test_people_lookup_found() -> None:
    # Проверка парсинга ответа People API при успешном нахождении профиля
    creds = GoogleSessionCredentials(sapisid="sap123")
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_res = MagicMock(spec=httpx.Response)
    mock_res.status_code = 200
    mock_res.json.return_value = {
        "responses": [
            {
                "person": {
                    "metadata": {
                        "sources": [{"type": "PROFILE", "id": "104857600000000001"}]
                    },
                    "names": [{"displayName": "Test Analyst"}],
                    "photos": [{"url": "https://lh3.googleusercontent.com/a/photo=s96-c"}],
                    "urls": [{"value": "https://www.youtube.com/channel/UC123456789"}],
                }
            }
        ]
    }
    mock_client.get.return_value = mock_res

    res = await lookup_people_data("analyst@example.com", creds, mock_client)
    assert res is not None
    assert res["gaia_id"] == "104857600000000001"
    assert res["display_name"] == "Test Analyst"
    assert res["is_workspace"] is True
    assert res["youtube_channel_id"] == "UC123456789"


async def test_people_lookup_not_found() -> None:
    # Проверка обработки несуществующего профиля в People API
    creds = GoogleSessionCredentials(sapisid="sap123")
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_res = MagicMock(spec=httpx.Response)
    mock_res.status_code = 404
    mock_client.get.return_value = mock_res

    res = await lookup_people_data("non_existent@gmail.com", creds, mock_client)
    assert res is None


async def test_google_checker_full_flow() -> None:
    # Проверка полного цикла чекера с получением Gaia ID, календаря и метаданных
    creds = GoogleSessionCredentials(sapisid="sap123")
    checker = GoogleAccountChecker(credentials=creds)

    mock_client = AsyncMock(spec=httpx.AsyncClient)

    def side_effect(url, **kwargs):
        res = MagicMock(spec=httpx.Response)
        res.status_code = 200
        if "peopleBatchGet" in str(url):
            res.json.return_value = {
                "responses": [
                    {
                        "person": {
                            "metadata": {
                                "sources": [{"type": "PROFILE", "id": "1122334455"}]
                            },
                            "names": [{"displayName": "Target User"}],
                            "photos": [{"url": "https://lh3.googleusercontent.com/a/xyz=s96-c"}],
                        }
                    }
                ]
            }
        elif "calendar" in str(url):
            res.text = '<script>var timeZone = "Europe/Kyiv";</script>'
        elif "maps/contrib" in str(url):
            res.text = "<html><body>Google Maps Profile</body></html>"
        return res

    mock_client.get.side_effect = side_effect

    target = TargetProfile(username="target_user@gmail.com")
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.FOUND
    assert result.platform_name == "Google"
    assert result.extracted_data is not None
    assert result.extracted_data["gaia_id"] == "1122334455"
    assert result.extracted_data["calendar_timezone"] == "Europe/Kyiv"
    assert result.extracted_data["display_name"] == "Target User"


def test_menu_slot_email_formatting() -> None:
    # Проверка логики форматирования слота 2
    slot_number = 2
    title = "eMail"
    clean_title = title.strip()
    if clean_title.startswith(f"{slot_number} >") or clean_title.startswith(f"{slot_number:>2} >"):
        formatted_label = clean_title
    else:
        formatted_label = f"{slot_number:>2} > {clean_title}"
    assert formatted_label == " 2 > eMail"
