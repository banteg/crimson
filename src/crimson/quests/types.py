from __future__ import annotations

from typing import Protocol

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


class QuestBuilder(Protocol):
    __name__: str

    def __call__(self, ctx: QuestContext) -> list[SpawnEntry]:
        ...


def parse_level(level: str) -> tuple[int, int]:
    return QuestLevel.parse(level).to_stage_pair()


def format_level(major: int, minor: int) -> str:
    return QuestLevel.from_parts(major, minor).to_string()


class QuestDefinition(msgspec.Struct, frozen=True, kw_only=True):
    major: int
    minor: int
    title: str
    builder: QuestBuilder
    time_limit_ms: int
    start_weapon_id: WeaponId
    terrain_slots: TerrainSlotTriplet
    unlock_perk_id: int | None = None
    unlock_weapon_id: WeaponId | None = None
    builder_address: int | None = None

    @property
    def level(self) -> str:
        return format_level(self.major, self.minor)

    @property
    def level_key(self) -> tuple[int, int]:
        return self.major, self.minor

    @property
    def level_value(self) -> QuestLevel:
        return QuestLevel.from_parts(self.major, self.minor)
