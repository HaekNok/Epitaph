# Модульные тесты чекеров сетевых сервисов
import pytest
from unittest.mock import AsyncMock, MagicMock
from epitaph.execution.checkers.github import GitHubChecker
from epitaph.execution.checkers.steam import SteamChecker
from epitaph.models.base import DetectionStatus, ExecutionType
from epitaph.models.target import TargetProfile


@pytest.mark.asyncio
async def test_github_checker_found() -> None:
    checker = GitHubChecker()
    target = TargetProfile(username="octocat")

    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "<html><body>Profile page</body></html>"
    mock_client.get.return_value = mock_response

    result = await checker.check_http(target, mock_client)
    assert result.status == DetectionStatus.FOUND
    assert result.profile_url == "https://github.com/octocat"
    assert result.execution_type == ExecutionType.HTTP


@pytest.mark.asyncio
async def test_github_checker_not_found() -> None:
    checker = GitHubChecker()
    target = TargetProfile(username="non_existent_404_user")

    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_response.text = "Not Found"
    mock_client.get.return_value = mock_response

    result = await checker.check_http(target, mock_client)
    assert result.status == DetectionStatus.NOT_FOUND
    assert result.profile_url is None


@pytest.mark.asyncio
async def test_steam_checker_http_blocked() -> None:
    checker = SteamChecker()
    target = TargetProfile(username="octocat")
    result = await checker.check_http(target, None)
    assert result.status == DetectionStatus.BLOCKED


@pytest.mark.asyncio
async def test_github_checker_browser_error() -> None:
    checker = GitHubChecker()
    target = TargetProfile(username="octocat")
    result = await checker.check_browser(target, None)
    assert result.status == DetectionStatus.ERROR
