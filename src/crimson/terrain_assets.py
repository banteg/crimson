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


__all__ = ["TerrainTextureId", "terrain_texture_by_id"]


_TERRAIN_TEXTURES: dict[TerrainTextureId, tuple[str, str]] = {
    TerrainTextureId.Q1_BASE: ("ter_q1_base", "ter/ter_q1_base.jaz"),
    TerrainTextureId.Q1_OVERLAY: ("ter_q1_tex1", "ter/ter_q1_tex1.jaz"),
    TerrainTextureId.Q2_BASE: ("ter_q2_base", "ter/ter_q2_base.jaz"),
    TerrainTextureId.Q2_OVERLAY: ("ter_q2_tex1", "ter/ter_q2_tex1.jaz"),
    TerrainTextureId.Q3_BASE: ("ter_q3_base", "ter/ter_q3_base.jaz"),
    TerrainTextureId.Q3_OVERLAY: ("ter_q3_tex1", "ter/ter_q3_tex1.jaz"),
    TerrainTextureId.Q4_BASE: ("ter_q4_base", "ter/ter_q4_base.jaz"),
    TerrainTextureId.Q4_OVERLAY: ("ter_q4_tex1", "ter/ter_q4_tex1.jaz"),
}


def terrain_texture_by_id(terrain_id: TerrainTextureId) -> tuple[str, str] | None:
    """Return (texture_cache_key, paq_relative_path) for a terrain texture ID."""
    try:
        key = TerrainTextureId(int(terrain_id))
    except ValueError:
        return None
    return _TERRAIN_TEXTURES.get(key)
