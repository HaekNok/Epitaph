from __future__ import annotations

import gzip
import importlib
import json
import logging
from pathlib import Path
import pkgutil
from typing import Dict, List, Optional, Type

from epitaph.execution.base import BasePlatformChecker
from epitaph.execution.generic import GenericPlatformChecker
from epitaph.models.site import SiteDefinition

logger = logging.getLogger("epitaph.execution.registry")

_REGISTRY: Dict[str, Type[BasePlatformChecker]] = {}
_GENERIC_CHECKERS: Optional[List[GenericPlatformChecker]] = None


def register_checker(cls: Type[BasePlatformChecker]) -> Type[BasePlatformChecker]:
    _REGISTRY[cls.__name__] = cls
    return cls


class CheckerRegistry:
    @classmethod
    def register(cls, checker_cls: Type[BasePlatformChecker]) -> None:
        _REGISTRY[checker_cls.__name__] = checker_cls

    @classmethod
    def load_sites_from_json(
        cls, data_path: Optional[Path] = None
    ) -> List[GenericPlatformChecker]:
        global _GENERIC_CHECKERS
        if _GENERIC_CHECKERS is not None and data_path is None:
            return _GENERIC_CHECKERS

        if data_path is None:
            pkg_dir = Path(__file__).resolve().parent.parent
            gz_path = pkg_dir / "data" / "sites.json.gz"
            json_path = pkg_dir / "data" / "sites.json"
            target_path = gz_path if gz_path.is_file() else json_path
            if not target_path.is_file():
                logger.warning("База данных сайтов не найдена: %s", target_path)
                return []
        else:
            target_path = data_path

        try:
            if target_path.suffix == ".gz":
                with gzip.open(target_path, "rt", encoding="utf-8") as f:
                    raw_data = json.load(f)
            else:
                with open(target_path, "r", encoding="utf-8") as f:
                    raw_data = json.load(f)

            items = raw_data if isinstance(raw_data, list) else raw_data.get("sites", [])
            checkers: List[GenericPlatformChecker] = []

            for item in items:
                try:
                    site_def = SiteDefinition.from_dict(item)
                    if not site_def.disabled:
                        checkers.append(GenericPlatformChecker(site_def))
                except Exception:
                    continue

            if data_path is None:
                _GENERIC_CHECKERS = checkers
            return checkers
        except Exception as err:
            logger.error("Сбой чтения базы сайтов из %s: %s", target_path, err)
            return []

    @classmethod
    def get_all_checkers(cls) -> List[BasePlatformChecker]:
        import epitaph.execution.checkers as checkers_pkg

        for _, module_name, _ in pkgutil.iter_modules(checkers_pkg.__path__):
            importlib.import_module(f"epitaph.execution.checkers.{module_name}")

        static_instances = [checker_cls() for checker_cls in _REGISTRY.values()]
        static_names = {c.name.lower() for c in static_instances}

        generic_instances = cls.load_sites_from_json()
        active_generics = [g for g in generic_instances if g.name.lower() not in static_names]

        return list(static_instances) + list(active_generics)
