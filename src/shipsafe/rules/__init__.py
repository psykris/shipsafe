"""Rule registry with auto-discovery."""

import importlib
import pkgutil
from pathlib import Path

from shipsafe.rules.base import Rule


def discover_rules() -> list[Rule]:
    """Discover and instantiate all Rule subclasses in the rules package."""
    rules = []
    package_path = Path(__file__).parent

    for module_info in pkgutil.iter_modules([str(package_path)]):
        if module_info.name == "base":
            continue
        module = importlib.import_module(f"shipsafe.rules.{module_info.name}")
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, Rule)
                and attr is not Rule
            ):
                rules.append(attr())

    return rules
