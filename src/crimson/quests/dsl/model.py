from __future__ import annotations

from dataclasses import dataclass

from ...terrain_slots import TerrainSlotTriplet
from ...weapons import WeaponId
from ..types import SpawnEntry


@dataclass(frozen=True)
class CompileLimits:
    source_bytes: int = 64 * 1024
    syntax_nodes: int = 10000
    syntax_depth: int = 64
    work: int = 100000
    collection: int = 4096
    entries: int = 256
    horizon_ms: int = 60 * 60 * 1000
    copies: int = 4096


@dataclass(frozen=True)
class SourceLocation:
    line: int
    iterations: tuple[int, ...]


@dataclass(frozen=True)
class QuestPlan:
    title: str
    version: int
    start_weapon_id: WeaponId
    terrain_slots: TerrainSlotTriplet
    entries: tuple[SpawnEntry, ...]
    locations: tuple[SourceLocation, ...]
