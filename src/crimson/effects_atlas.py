from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

__all__ = [
    "EFFECT_ID_ATLAS_TABLE",
    "EFFECT_ID_ATLAS_TABLE_BY_ID",
    "EffectId",
    "EffectAtlasEntry",
    "SIZE_CODE_GRID",
    "effect_src_rect",
]


SIZE_CODE_GRID: dict[int, int] = {
    0x10: 16,
    0x20: 8,
    0x40: 4,
    0x80: 2,
}


@dataclass(frozen=True, slots=True)
class EffectAtlasEntry:
    effect_id: int
    size_code: int
    frame: int

    @property
    def grid(self) -> int:
        return SIZE_CODE_GRID[self.size_code]


# Extracted from `effect_id_table` (`size_code`, `frame`) (see `docs/structs/effects.md`).
EFFECT_ID_ATLAS_TABLE: tuple[EffectAtlasEntry, ...] = (
    EffectAtlasEntry(0x00, 0x80, 0x02),
    EffectAtlasEntry(0x01, 0x80, 0x03),
    EffectAtlasEntry(0x02, 0x20, 0x00),
    EffectAtlasEntry(0x03, 0x20, 0x01),
    EffectAtlasEntry(0x04, 0x20, 0x02),
    EffectAtlasEntry(0x05, 0x20, 0x03),
    EffectAtlasEntry(0x06, 0x20, 0x04),
    EffectAtlasEntry(0x07, 0x20, 0x05),
    EffectAtlasEntry(0x08, 0x20, 0x08),
    EffectAtlasEntry(0x09, 0x20, 0x09),
    EffectAtlasEntry(0x0A, 0x20, 0x0A),
    EffectAtlasEntry(0x0B, 0x20, 0x0B),
    EffectAtlasEntry(0x0C, 0x40, 0x05),
    EffectAtlasEntry(0x0D, 0x40, 0x03),
    EffectAtlasEntry(0x0E, 0x40, 0x04),
    EffectAtlasEntry(0x0F, 0x40, 0x05),
    EffectAtlasEntry(0x10, 0x40, 0x06),
    EffectAtlasEntry(0x11, 0x40, 0x07),
    EffectAtlasEntry(0x12, 0x10, 0x26),
)

EFFECT_ID_ATLAS_TABLE_BY_ID: dict[int, EffectAtlasEntry] = {entry.effect_id: entry for entry in EFFECT_ID_ATLAS_TABLE}


class EffectId(IntEnum):
    BURST = 0x00
    RING = 0x01
    SHIELD_RING = 0x02
    EFFECT_03 = 0x03
    EFFECT_04 = 0x04
    EFFECT_05 = 0x05
    EFFECT_06 = 0x06
    BLOOD_SPLATTER = 0x07
    FREEZE_SHARD_0 = 0x08
    FREEZE_SHARD_1 = 0x09
    FREEZE_SHARD_2 = 0x0A
    EFFECT_0B = 0x0B
    EXPLOSION_BURST = 0x0C
    GLOW = 0x0D
    FREEZE_SHATTER = 0x0E
    EFFECT_0F = 0x0F
    AURA = 0x10
    EXPLOSION_PUFF = 0x11
    CASING = 0x12


def effect_src_rect(effect_id: int, *, texture_width: float, texture_height: float) -> tuple[float, float, float, float] | None:
    entry = EFFECT_ID_ATLAS_TABLE_BY_ID.get(int(effect_id))
    if entry is None:
        return None

    grid = SIZE_CODE_GRID.get(entry.size_code)
    if not grid:
        return None

    frame = int(entry.frame)
    col = frame % grid
    row = frame // grid
    cell_w = float(texture_width) / float(grid)
    cell_h = float(texture_height) / float(grid)
    return cell_w * float(col), cell_h * float(row), cell_w, cell_h
