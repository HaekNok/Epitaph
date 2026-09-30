"""Реестр модулей проверки сервисов по email."""
from __future__ import annotations

from typing import Callable, Dict, List, Type

from epitaph.execution.checkers.email.base import BaseEmailChecker


class EmailCheckerRegistry:
    """Потокобезопасный реестр зарегистрированных модулей проверки email."""

    _registry: Dict[str, Type[BaseEmailChecker]] = {}

    @classmethod
    def register(cls, name: str) -> Callable[[Type[BaseEmailChecker]], Type[BaseEmailChecker]]:
        """Декоратор для декларативной регистрации класса чекера."""

        def decorator(checker_cls: Type[BaseEmailChecker]) -> Type[BaseEmailChecker]:
            cls._registry[name.lower()] = checker_cls
            return checker_cls

        return decorator

    @classmethod
    def _ensure_services_loaded(cls) -> None:
        """Гарантированная загрузка всех платформенных чекеров из единого модуля executor."""
        try:
            import epitaph.execution.checkers.email.executor  # noqa: F401
        except ImportError:
            pass

    @classmethod
    def get_all_instances(cls) -> List[BaseEmailChecker]:
        """Инстанцирование всех зарегистрированных чекеров."""
        cls._ensure_services_loaded()
        return [checker_cls() for checker_cls in cls._registry.values()]

    @classmethod
    def get_checker(cls, name: str) -> BaseEmailChecker:
        """Получение экземпляра чекера по системному имени."""
        cls._ensure_services_loaded()
        normalized = name.lower()
        if normalized not in cls._registry:
            raise KeyError(f"Email чекер '{name}' не зарегистрирован")
        return cls._registry[normalized]()
