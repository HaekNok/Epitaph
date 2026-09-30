"""Пакет специализированных сервисов проверки email."""
from epitaph.execution.checkers.email.services.github import GitHubEmailChecker
from epitaph.execution.checkers.email.services.twitter import TwitterEmailChecker
from epitaph.execution.checkers.email.services.instagram import InstagramEmailChecker
from epitaph.execution.checkers.email.services.discord import DiscordEmailChecker
from epitaph.execution.checkers.email.services.spotify import SpotifyEmailChecker
from epitaph.execution.checkers.email.services.gravatar import GravatarEmailChecker

__all__ = [
    "GitHubEmailChecker",
    "TwitterEmailChecker",
    "InstagramEmailChecker",
    "DiscordEmailChecker",
    "SpotifyEmailChecker",
    "GravatarEmailChecker",
]
