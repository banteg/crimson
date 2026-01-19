from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True, slots=True)
class QuestContext:
    width: int
    height: int
    player_count: int


@dataclass(frozen=True, slots=True)
class SpawnEntry:
    x: float
    y: float
    heading: float
    spawn_id: int
    trigger_ms: int
    count: int


QuestBuilder = Callable[..., list[SpawnEntry]]


@dataclass(frozen=True, slots=True, kw_only=True)
class QuestDefinition:
    level: str
    title: str
    builder: QuestBuilder
    time_limit_ms: int
    start_weapon_id: int
    unlock_perk_id: int | None = None
    unlock_weapon_id: int | None = None
    terrain_id: int | None = None
    builder_address: int | None = None
