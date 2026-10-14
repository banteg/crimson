"""Custom quests: a resolved spawn table the classic quest start loads instead of a stock builder."""

from __future__ import annotations

import hashlib
import math
import struct
from collections.abc import Sequence

import msgspec

from grim.geom import Vec2

from ..bonuses.ids import BonusId
from ..creatures.spawn import SpawnId
from ..math_parity import f32
from ..perks.ids import PerkId
from ..terrain_slots import TerrainSlotTriplet
from ..weapons import WeaponId
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
DROPPABLE_WEAPONS: tuple[WeaponId, ...] = tuple(WeaponId(i) for i in range(2, 34))
PORTABLE_QUEST_HEAD = struct.Struct("<10I")
PORTABLE_QUEST_SPAWN = struct.Struct("<3f3i")
PORTABLE_QUEST_BYTES = PORTABLE_QUEST_HEAD.size + MAX_ENTRIES * PORTABLE_QUEST_SPAWN.size

def pack_no_bonuses(no_bonuses: Sequence[BonusId]) -> int:
    return sum(1 << int(bonus_id) for bonus_id in no_bonuses)


def unpack_no_bonuses(mask: int) -> tuple[BonusId, ...]:
    return tuple(BonusId(i) for i in range(2, 15) if mask & (1 << i))


def pack_no_perks(no_perks: Sequence[PerkId]) -> tuple[int, int]:
    bits = sum(1 << int(perk_id) for perk_id in no_perks)
    return bits & 0xFFFFFFFF, (bits >> 32) & 0xFFFFFFFF


def unpack_no_perks(lo: int, hi: int) -> tuple[PerkId, ...]:
    bits = (int(hi) << 32) | (int(lo) & 0xFFFFFFFF)
    return tuple(PerkId(i) for i in range(1, 58) if bits & (1 << i))


def pack_no_weapons(no_weapons: Sequence[WeaponId]) -> tuple[int, int]:
    bits = sum(1 << int(weapon_id) for weapon_id in no_weapons)
    return bits & 0xFFFFFFFF, (bits >> 32) & 0xFFFFFFFF


def unpack_no_weapons(lo: int, hi: int) -> tuple[WeaponId, ...]:
    bits = (int(hi) << 32) | (int(lo) & 0xFFFFFFFF)
    return tuple(WeaponId(i) for i in range(2, 34) if bits & (1 << i))


class CustomQuest(msgspec.Struct, frozen=True, kw_only=True, forbid_unknown_fields=True):
    """A custom quest as every runtime plays it: resolved entries and drop/offer restrictions, no recipe."""

    title: str
    # Presentation, like the title: who wrote it, as the recipe says.
    author: str | None = None
    start_weapon_id: WeaponId
    terrain_slots: TerrainSlotTriplet
    entries: tuple[SpawnEntry, ...]
    no_bonuses: tuple[BonusId, ...] = ()
    no_perks: tuple[PerkId, ...] = ()
    no_weapons: tuple[WeaponId, ...] = ()

    @property
    def byline(self) -> str:
        """What the quest title shows under a custom quest's title."""
        return "" if self.author is None else f"by {self.author}"

    def to_portable_bytes(self) -> bytes:
        perks_lo, perks_hi = pack_no_perks(self.no_perks)
        weapons_lo, weapons_hi = pack_no_weapons(self.no_weapons)
        head = PORTABLE_QUEST_HEAD.pack(
            int(self.start_weapon_id),
            *self.terrain_slots,
            len(self.entries),
            pack_no_bonuses(self.no_bonuses),
            perks_lo,
            perks_hi,
            weapons_lo,
            weapons_hi,
        )
        entries = b"".join(
            PORTABLE_QUEST_SPAWN.pack(e.pos.x, e.pos.y, e.heading, int(e.spawn_id), e.trigger_ms, e.count)
            for e in self.entries
        )
        return (head + entries).ljust(PORTABLE_QUEST_BYTES, b"\0")

    @classmethod
    def from_portable_bytes(cls, blob: bytes, *, title: str = "Custom quest") -> CustomQuest:
        weapon, t0, t1, t2, count, bonuses, perks_lo, perks_hi, weapons_lo, weapons_hi = (
            PORTABLE_QUEST_HEAD.unpack_from(blob)
        )
        entries = tuple(
            SpawnEntry(pos=Vec2(x, y), heading=heading, spawn_id=SpawnId(template), trigger_ms=trigger, count=copies)
            for x, y, heading, template, trigger, copies in PORTABLE_QUEST_SPAWN.iter_unpack(
                blob[PORTABLE_QUEST_HEAD.size : PORTABLE_QUEST_HEAD.size + count * PORTABLE_QUEST_SPAWN.size],
            )
        )
        return cls(
            title=title,
            start_weapon_id=WeaponId(weapon),
            terrain_slots=(t0, t1, t2),
            entries=entries,
            no_bonuses=unpack_no_bonuses(bonuses),
            no_perks=unpack_no_perks(perks_lo, perks_hi),
            no_weapons=unpack_no_weapons(weapons_lo, weapons_hi),
        )

    def digest(self) -> str:
        """SHA-256 of everything that plays; the title and author are presentation."""
        return hashlib.sha256(self.to_portable_bytes()).hexdigest()

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
    if quest.start_weapon_id == WeaponId.NONE or quest.start_weapon_id.name.startswith("UNUSED_"):
        raise ValueError("a custom quest needs a starting weapon")
    if not all(0 <= slot <= 7 for slot in quest.terrain_slots):
        raise ValueError("terrain slots must be in 0..7")
    if list(quest.no_bonuses) != sorted(set(quest.no_bonuses)) or any(
        not 2 <= int(bonus_id) <= 14 for bonus_id in quest.no_bonuses
    ):
        raise ValueError("no_bonuses must be strictly ascending bonus IDs in 2..14")
    if list(quest.no_perks) != sorted(set(quest.no_perks)) or any(
        not 1 <= int(perk_id) <= 57 for perk_id in quest.no_perks
    ):
        raise ValueError("no_perks must be strictly ascending perk IDs in 1..57")
    if list(quest.no_weapons) != sorted(set(quest.no_weapons)) or any(
        not 2 <= int(weapon_id) <= 33 for weapon_id in quest.no_weapons
    ):
        raise ValueError("no_weapons must be strictly ascending weapon IDs in 2..33")
    check_table(quest.entries)
