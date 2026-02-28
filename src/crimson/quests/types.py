from __future__ import annotations

from typing import Protocol

import msgspec

from grim.geom import Vec2

from ..creatures.spawn import SpawnId
from ..terrain_assets import TerrainTextureId
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
    major_text, minor_text = level.split(".", 1)
    return int(major_text), int(minor_text)


def format_level(major: int, minor: int) -> str:
    return f"{int(major)}.{int(minor)}"


def _level_parts(level_or_major: str | int, minor: int | None = None) -> tuple[int, int]:
    if isinstance(level_or_major, str):
        return parse_level(level_or_major)
    if minor is None:
        raise TypeError("minor is required when major is passed as an int")
    return int(level_or_major), int(minor)


def terrain_ids_for(level_or_major: str | int, minor: int | None = None) -> tuple[int, int, int]:
    tier, quest = _level_parts(level_or_major, minor)
    if tier <= 4:
        base = (tier - 1) * 2
        alt = base + 1
        if quest < 6:
            return base, alt, base
        return base, base, alt
    return quest & 0x3, TerrainTextureId.Q1_OVERLAY, TerrainTextureId.Q2_OVERLAY


class QuestDefinition(msgspec.Struct, frozen=True, kw_only=True):
    major: int
    minor: int
    title: str
    builder: QuestBuilder
    time_limit_ms: int
    start_weapon_id: WeaponId
    unlock_perk_id: int | None = None
    unlock_weapon_id: WeaponId | None = None
    terrain_ids: tuple[int, int, int] | None = None
    builder_address: int | None = None

    @property
    def level(self) -> str:
        return format_level(self.major, self.minor)

    @property
    def level_key(self) -> tuple[int, int]:
        return self.major, self.minor
