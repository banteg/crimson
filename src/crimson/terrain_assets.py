from __future__ import annotations

from enum import IntEnum


class TerrainTextureId(IntEnum):
    Q1_BASE = 0
    Q1_OVERLAY = 1
    Q2_BASE = 2
    Q2_OVERLAY = 3
    Q3_BASE = 4
    Q3_OVERLAY = 5
    Q4_BASE = 6
    Q4_OVERLAY = 7
    FB_Q1 = 8
    FB_Q2 = 9
    FB_Q3 = 10
    FB_Q4 = 11


__all__ = ["TerrainTextureId"]
