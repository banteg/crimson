from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .database import QUESTS, quest_by_level
    from .types import QuestContext, QuestDefinition, SpawnEntry

__all__ = ["QUESTS", "QuestContext", "QuestDefinition", "SpawnEntry", "quest_by_level"]

# The quest database pulls the terrain tables (and raylib through them), so the package loads it on first use:
# `crimson.quests.level` stays importable from headless CLI startup.
_LAZY = {
    "QUESTS": ".database",
    "quest_by_level": ".database",
    "QuestContext": ".types",
    "QuestDefinition": ".types",
    "SpawnEntry": ".types",
}


def __getattr__(name: str) -> Any:
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module, __name__), name)
    globals()[name] = value
    return value
