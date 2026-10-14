"""Custom quests: a resolved spawn table the classic quest start loads instead of a stock builder."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Sequence

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
# A full arena beyond each edge: room for every off-arena arrival the stock quests use (up to 1280), and far from
# the distances whose squares overflow float32 in gameplay.
MIN_COORDINATE = -1024.0
MAX_COORDINATE = 2048.0
MAX_TITLE_CHARS = 64
# As long as a player name, which a published quest's author will be.
MAX_AUTHOR_CHARS = 31
VARIANT_COUNT = 8


def variant_index(*, player_count: int, hardcore: bool) -> int:
    """Variants run over player counts 1..4, each normal then hardcore."""
    return (player_count - 1) * 2 + int(hardcore)


class CustomQuest(msgspec.Struct, frozen=True, kw_only=True, forbid_unknown_fields=True):
    """A custom quest as every runtime plays it: resolved entries, no recipe.

    `tables` holds each distinct table with base counts and `variants` picks one per
    `variant_index`. The game's hardcore count rule applies when a run starts, as it
    does for stock quests.
    """

    title: str
    # Presentation, like the title: who wrote it, as the recipe says until publishing vouches for it.
    author: str | None = None
    start_weapon_id: WeaponId
    terrain_slots: TerrainSlotTriplet
    tables: tuple[tuple[SpawnEntry, ...], ...]
    variants: tuple[int, ...]

    def entries(self, *, player_count: int, hardcore: bool) -> tuple[SpawnEntry, ...]:
        table = self.tables[self.variants[variant_index(player_count=player_count, hardcore=hardcore)]]
        return tuple(apply_hardcore_spawn_table_adjustment(list(table))) if hardcore else table

    @property
    def byline(self) -> str:
        """What the quest title shows under a custom quest's title."""
        return "" if self.author is None else f"by {self.author}"

    def digest(self) -> str:
        """SHA-256 of everything that plays; the title and author are presentation."""
        gameplay = (self.start_weapon_id, self.terrain_slots, self.tables, self.variants)
        return hashlib.sha256(msgspec.msgpack.encode(gameplay)).hexdigest()


def check_table(entries: Sequence[SpawnEntry]) -> None:
    """A table a run can play: its entries, and what they spawn after the hardcore rule.

    Copies are template invocations; formations and nests add their own creatures on top.
    """
    if not 1 <= len(entries) <= MAX_ENTRIES:
        raise ValueError(f"a table holds 1..{MAX_ENTRIES} entries")
    per_trigger: dict[int, int] = {}
    for entry in entries:
        if entry.spawn_id == SpawnId.UNUSED_02:
            raise ValueError("unused spawn template")
        if not 0 <= entry.trigger_ms <= MAX_TRIGGER_MS:
            raise ValueError(f"trigger times must be in 0..{MAX_TRIGGER_MS} ms")
        for coordinate in (entry.pos.x, entry.pos.y):
            if not MIN_COORDINATE <= coordinate <= MAX_COORDINATE:
                raise ValueError(f"positions must be in {MIN_COORDINATE:g}..{MAX_COORDINATE:g}")
            _check_f32(coordinate, "positions")
        _check_f32(entry.heading, "headings")
        if not 1 <= entry.count <= MAX_COPIES:
            raise ValueError(f"an entry spawns {entry.count} copies; the limit is {MAX_COPIES}")
        per_trigger[entry.trigger_ms] = per_trigger.get(entry.trigger_ms, 0) + entry.count
    for trigger_ms, copies in per_trigger.items():
        if copies > MAX_TRIGGER_COPIES:
            raise ValueError(f"{copies} copies at {trigger_ms} ms exceed the per-trigger copy limit")
    if sum(per_trigger.values()) > MAX_TOTAL_COPIES:
        raise ValueError("total copies exceed the quest copy limit")


def _check_f32(value: float, what: str) -> None:
    try:
        canonical = math.isfinite(value) and f32(value) == value
    except OverflowError:
        canonical = False
    if not canonical:
        raise ValueError(f"{what} must be finite float32 values")


def _printable(text: str, limit: int) -> bool:
    return 1 <= len(text) <= limit and all(" " <= char <= "~" for char in text)


def check_author(author: str) -> None:
    if not _printable(author, MAX_AUTHOR_CHARS):
        raise ValueError(f"author must be 1..{MAX_AUTHOR_CHARS} printable ASCII characters")


def validate_custom_quest(quest: CustomQuest) -> None:
    """Everything a runtime needs to trust before it plays a custom quest."""
    if not _printable(quest.title, MAX_TITLE_CHARS):
        raise ValueError(f"title must be 1..{MAX_TITLE_CHARS} printable ASCII characters")
    if quest.author is not None:
        check_author(quest.author)
    if quest.start_weapon_id == WeaponId.NONE:
        raise ValueError("a custom quest needs a starting weapon")
    if not all(0 <= slot <= 7 for slot in quest.terrain_slots):
        raise ValueError("terrain slots must be in 0..7")
    if len(quest.variants) != VARIANT_COUNT or sorted(set(quest.variants)) != list(range(len(quest.tables))):
        raise ValueError(
            f"variants must pick one of the tables for each of {VARIANT_COUNT} variants, using every table",
        )
    # Every table is some variant's, so checking each distinct (table, hardcore) pair checks them all.
    checked: set[tuple[int, bool]] = set()
    for player_count in (1, 2, 3, 4):
        for hardcore in (False, True):
            pair = (quest.variants[variant_index(player_count=player_count, hardcore=hardcore)], hardcore)
            if pair not in checked:
                checked.add(pair)
                check_table(quest.entries(player_count=player_count, hardcore=hardcore))
