from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from grim.geom import Vec2

from ..creatures.spawn import SpawnId
from ..terrain_assets import TerrainTextureId


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


@dataclass(frozen=True, slots=True, kw_only=True)
class QuestDefinition:
    major: int
    minor: int
    title: str
    builder: QuestBuilder
    time_limit_ms: int
    start_weapon_id: int
    unlock_perk_id: int | None = None
    unlock_weapon_id: int | None = None
    terrain_ids: tuple[int, int, int] | None = None
    builder_address: int | None = None

    @property
    def level(self) -> str:
        return format_level(self.major, self.minor)

    @property
    def level_key(self) -> tuple[int, int]:
        return self.major, self.minor
