from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from grim.geom import Vec2

from ..creatures.spawn import SpawnId


@dataclass(frozen=True, slots=True)
class QuestContext:
    width: int
    height: int
    player_count: int


@dataclass(frozen=True, slots=True, kw_only=True)
class SpawnEntry:
    pos: Vec2
    heading: float
    spawn_id: SpawnId
    trigger_ms: int
    count: int


QuestBuilder = Callable[..., list[SpawnEntry]]


def terrain_ids_for(level: str) -> tuple[int, int, int]:
    tier_text, quest_text = level.split(".", 1)
    tier = int(tier_text)
    quest = int(quest_text)
    if tier <= 4:
        base = (tier - 1) * 2
        alt = base + 1
        if quest < 6:
            return base, alt, base
        return base, base, alt
    return quest & 0x3, 1, 3


def terrain_id_for(level: str) -> int:
    return terrain_ids_for(level)[0]


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
    terrain_ids: tuple[int, int, int] | None = None
    builder_address: int | None = None

    def __post_init__(self) -> None:
        terrain_ids = self.terrain_ids
        if terrain_ids is None:
            terrain_ids = terrain_ids_for(self.level)
            object.__setattr__(self, "terrain_ids", terrain_ids)
        if self.terrain_id is None:
            object.__setattr__(self, "terrain_id", terrain_ids[0])

    @property
    def level_key(self) -> tuple[int, int]:
        tier_text, quest_text = self.level.split(".", 1)
        return int(tier_text), int(quest_text)
