from __future__ import annotations

from collections.abc import Callable
from typing import TypeAlias

import msgspec

from crimson.quests.level import QuestLevel
from grim.geom import Vec2

from ..creatures.spawn import SpawnId
from ..terrain_slots import TerrainSlotTriplet
from ..weapons import WeaponId


class QuestContext(msgspec.Struct, frozen=True):
    width: int
    height: int
    player_count: int


class SpawnEntry(msgspec.Struct, frozen=True, kw_only=True):
    pos: Vec2
    heading: float
    spawn_id: SpawnId
    trigger_ms: int
    count: int


QuestBuilder: TypeAlias = Callable[..., list[SpawnEntry]]


class QuestDefinition(msgspec.Struct, frozen=True, kw_only=True):
    level: QuestLevel
    title: str
    builder: QuestBuilder
    time_limit_ms: int
    start_weapon_id: WeaponId
    terrain_slots: TerrainSlotTriplet
    unlock_perk_id: int | None = None
    unlock_weapon_id: WeaponId | None = None

    @property
    def major(self) -> int:
        return int(self.level.major)

    @property
    def minor(self) -> int:
        return int(self.level.minor)
