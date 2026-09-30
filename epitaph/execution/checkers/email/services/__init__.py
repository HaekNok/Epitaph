"""Пакет специализированных сервисов проверки email."""
from epitaph.execution.checkers.email.services.discord import DiscordEmailChecker
from epitaph.execution.checkers.email.services.github import GitHubEmailChecker
from epitaph.execution.checkers.email.services.headhunter import HeadhunterEmailChecker
from epitaph.execution.checkers.email.services.robota import RobotaUaEmailChecker
from epitaph.execution.checkers.email.services.snapchat import SnapchatEmailChecker
from epitaph.execution.checkers.email.services.steam import SteamEmailChecker
from epitaph.execution.checkers.email.services.tiktok import TikTokEmailChecker
from epitaph.execution.checkers.email.services.workua import WorkUaEmailChecker

__all__ = [
    "DiscordEmailChecker",
    "GitHubEmailChecker",
    "HeadhunterEmailChecker",
    "RobotaUaEmailChecker",
    "SnapchatEmailChecker",
    "SteamEmailChecker",
    "TikTokEmailChecker",
    "WorkUaEmailChecker",
]
