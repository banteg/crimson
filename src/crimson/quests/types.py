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


def terrain_id_for(level: str) -> int:
    tier_text, quest_text = level.split(".", 1)
    tier = int(tier_text)
    quest = int(quest_text)
    if tier <= 4:
        return (tier - 1) * 2
    return quest & 0x3


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

    def __post_init__(self) -> None:
        if self.terrain_id is None:
            object.__setattr__(self, "terrain_id", terrain_id_for(self.level))
