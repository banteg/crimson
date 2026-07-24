from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .types import QuestContext, QuestDefinition, SpawnEntry

__all__ = [
    "QuestContext",
    "QuestDefinition",
    "SpawnEntry",
    "all_quests",
    "quest_by_level",
    "tier1",
    "tier2",
    "tier3",
    "tier4",
    "tier5",
]

_TIERS = ("tier1", "tier2", "tier3", "tier4", "tier5")
_TYPES = {"QuestContext", "QuestDefinition", "SpawnEntry"}
_tiers_loaded = False


def _load_tiers() -> None:
    global _tiers_loaded
    if _tiers_loaded:
        return
    for module_name in _TIERS:
        import_module(f".{module_name}", __name__)
    _tiers_loaded = True


def all_quests():
    _load_tiers()
    from .registry import all_quests as collect

    return collect()


def quest_by_level(level):
    _load_tiers()
    from .registry import quest_by_level as lookup

    return lookup(level)


def __getattr__(name: str) -> Any:
    if name in _TIERS:
        value = import_module(f".{name}", __name__)
    elif name in _TYPES:
        value = getattr(import_module(".types", __name__), name)
    else:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    globals()[name] = value
    return value
