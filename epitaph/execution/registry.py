import importlib
import pkgutil
from typing import Dict, List, Type
from epitaph.execution.base import BasePlatformChecker

_REGISTRY: Dict[str, Type[BasePlatformChecker]] = {}


def register_checker(cls: Type[BasePlatformChecker]) -> Type[BasePlatformChecker]:
    _REGISTRY[cls.__name__] = cls
    return cls


class CheckerRegistry:
    @classmethod
    def register(cls, checker_cls: Type[BasePlatformChecker]) -> None:
        _REGISTRY[checker_cls.__name__] = checker_cls

    @classmethod
    def get_all_checkers(cls) -> List[BasePlatformChecker]:
        import epitaph.execution.checkers as checkers_pkg
        for _, module_name, _ in pkgutil.iter_modules(checkers_pkg.__path__):
            importlib.import_module(f"epitaph.execution.checkers.{module_name}")

        return [checker_cls() for checker_cls in _REGISTRY.values()]
