from __future__ import annotations

from dataclasses import dataclass

from ...terrain_slots import TerrainSlotTriplet
from ...weapons import WeaponId
from ..types import SpawnEntry


@dataclass(frozen=True)
class CompileLimits:
    """Construction bounds; what a quest may spawn is bounded in `quests.custom`."""

    source_bytes: int = 64 * 1024
    syntax_nodes: int = 10000
    syntax_depth: int = 64
    work: int = 100000
    collection: int = 4096


@dataclass(frozen=True)
class SourceLocation:
    """Where an entry came from; unique per entry within a plan."""

    line: int
    iterations: tuple[int, ...]
    calls: tuple[int, ...] = ()  # pattern call-site lines, outermost first
    item: int = 0  # position within a place list


@dataclass(frozen=True)
class QuestPlan:
    title: str
    version: int
    start_weapon_id: WeaponId
    terrain_slots: TerrainSlotTriplet
    entries: tuple[SpawnEntry, ...]
    locations: tuple[SourceLocation, ...]
