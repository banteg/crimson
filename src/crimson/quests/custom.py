"""Custom quests: a resolved spawn table the classic quest start loads instead of a stock builder."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Iterable

import msgspec

from ..creatures.spawn import SpawnId
from ..math_parity import f32
from ..terrain_slots import TerrainSlotTriplet
from ..weapons import WeaponId
from .runtime import apply_hardcore_spawn_table_adjustment
from .types import SpawnEntry

# The native spawn table holds 256 entries, and copies spawn into a 384-creature pool.
MAX_ENTRIES = 256
MAX_COPIES = 384
MAX_TRIGGER_COPIES = 384
MAX_TOTAL_COPIES = 8192
MAX_TRIGGER_MS = 60 * 60 * 1000
MAX_TITLE_CHARS = 64
VARIANT_COUNT = 8


def variant_index(*, player_count: int, hardcore: bool) -> int:
    """Variants run over player counts 1..4, each normal then hardcore."""
    return (player_count - 1) * 2 + int(hardcore)


class CustomQuest(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """A custom quest as every runtime plays it: resolved entries, no recipe.

    `tables` holds each distinct table with base counts and `variants` picks one per
    `variant_index`. The game's hardcore count rule applies when a run starts, as it
    does for stock quests.
    """

    title: str
    start_weapon_id: WeaponId
    terrain_slots: TerrainSlotTriplet
    tables: tuple[tuple[SpawnEntry, ...], ...]
    variants: tuple[int, ...]

    def entries(self, *, player_count: int, hardcore: bool) -> tuple[SpawnEntry, ...]:
        table = self.tables[self.variants[variant_index(player_count=player_count, hardcore=hardcore)]]
        return tuple(apply_hardcore_spawn_table_adjustment(list(table))) if hardcore else table

    def digest(self) -> str:
        """SHA-256 of everything that plays; the title is presentation."""
        gameplay = (self.start_weapon_id, self.terrain_slots, self.tables, self.variants)
        return hashlib.sha256(msgspec.msgpack.encode(gameplay)).hexdigest()


def check_spawn_limits(entries: Iterable[SpawnEntry]) -> None:
    """Copies are template invocations; formations and nests add their own creatures on top."""
    per_trigger: dict[int, int] = {}
    for entry in entries:
        if not 1 <= entry.count <= MAX_COPIES:
            raise ValueError(f"an entry spawns {entry.count} copies; the limit is {MAX_COPIES}")
        per_trigger[entry.trigger_ms] = per_trigger.get(entry.trigger_ms, 0) + entry.count
    for trigger_ms, copies in per_trigger.items():
        if copies > MAX_TRIGGER_COPIES:
            raise ValueError(f"{copies} copies at {trigger_ms} ms exceed the per-trigger copy limit")
    if sum(per_trigger.values()) > MAX_TOTAL_COPIES:
        raise ValueError("total copies exceed the quest copy limit")


def _check_f32(value: float, what: str) -> None:
    if not math.isfinite(value) or f32(value) != value:
        raise ValueError(f"{what} must be a finite float32")


def validate_custom_quest(quest: CustomQuest) -> None:
    """Everything a runtime needs to trust before it plays a custom quest."""
    if not 1 <= len(quest.title) <= MAX_TITLE_CHARS or not all(" " <= char <= "~" for char in quest.title):
        raise ValueError(f"title must be 1..{MAX_TITLE_CHARS} printable ASCII characters")
    if quest.start_weapon_id == WeaponId.NONE:
        raise ValueError("a custom quest needs a starting weapon")
    if not all(0 <= slot <= 7 for slot in quest.terrain_slots):
        raise ValueError("terrain slots must be in 0..7")
    if len(quest.variants) != VARIANT_COUNT or sorted(set(quest.variants)) != list(range(len(quest.tables))):
        raise ValueError(
            f"variants must pick one of the tables for each of {VARIANT_COUNT} variants, using every table",
        )
    for table in quest.tables:
        if not 1 <= len(table) <= MAX_ENTRIES:
            raise ValueError(f"a table holds 1..{MAX_ENTRIES} entries")
        for entry in table:
            if entry.spawn_id == SpawnId.UNUSED_02:
                raise ValueError("unused spawn template")
            if not 0 <= entry.trigger_ms <= MAX_TRIGGER_MS:
                raise ValueError(f"trigger times must be in 0..{MAX_TRIGGER_MS} ms")
            _check_f32(entry.pos.x, "positions")
            _check_f32(entry.pos.y, "positions")
            _check_f32(entry.heading, "headings")
    for player_count in (1, 2, 3, 4):
        for hardcore in (False, True):
            check_spawn_limits(quest.entries(player_count=player_count, hardcore=hardcore))
