# Тесты для GenericPlatformChecker и загрузки декларативной базы сайтов
import pytest
from unittest.mock import AsyncMock, MagicMock
from epitaph.execution.generic import GenericPlatformChecker
from epitaph.execution.registry import CheckerRegistry
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.site import CheckType, SiteDefinition
from epitaph.models.target import TargetProfile


@pytest.mark.asyncio
async def test_generic_checker_status_code_found() -> None:
    # Проверка обнаружения профиля по коду статуса 200
    site = SiteDefinition(
        name="GitLab",
        url="https://gitlab.com/{username}",
        check_type=CheckType.STATUS_CODE,
        error_code=404,
    )
    checker = GenericPlatformChecker(site)
    target = TargetProfile(username="alex")

    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_client.get.return_value = mock_response

    result = await checker.check_http(target, mock_client)
    assert result.status == DetectionStatus.FOUND
    assert result.profile_url == "https://gitlab.com/alex"


@pytest.mark.asyncio
async def test_generic_checker_status_code_not_found() -> None:
    # Проверка фиксации отсутствия профиля по коду 404
    site = SiteDefinition(
        name="GitLab",
        url="https://gitlab.com/{username}",
        check_type=CheckType.STATUS_CODE,
        error_code=404,
    )
    checker = GenericPlatformChecker(site)
    target = TargetProfile(username="non_existent")

    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_client.get.return_value = mock_response

    result = await checker.check_http(target, mock_client)
    assert result.status == DetectionStatus.NOT_FOUND
    assert result.profile_url is None


@pytest.mark.asyncio
async def test_generic_checker_regex_prefilter_skip() -> None:
    # Проверка клиентского отсечения невалидного никнейма без сетевого запроса
    site = SiteDefinition(
        name="StrictSite",
        url="https://example.org/{username}",
        regex_check="^[a-z]{5,10}$",
    )
    checker = GenericPlatformChecker(site)
    target = TargetProfile(username="123")

    mock_client = AsyncMock()
    result = await checker.check_http(target, mock_client)

    assert result.status == DetectionStatus.NOT_FOUND
    mock_client.get.assert_not_called()


@pytest.mark.asyncio
async def test_generic_checker_message_check() -> None:
    # Проверка детектирования по наличию текстового маркера ошибки
    site = SiteDefinition(
        name="WikiForum",
        url="https://wiki.example.org/{username}",
        check_type=CheckType.MESSAGE,
        error_message="User does not exist",
    )
    checker = GenericPlatformChecker(site)
    target = TargetProfile(username="ghost")

    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "<html><body>User does not exist in our database</body></html>"
    mock_client.get.return_value = mock_response

    result = await checker.check_http(target, mock_client)
    assert result.status == DetectionStatus.NOT_FOUND


def test_checker_registry_load_sites() -> None:
    # Проверка загрузки и корректного подсчета сайтов из декларативной базы
    checkers = CheckerRegistry.load_sites_from_json()
    assert len(checkers) >= 2900
