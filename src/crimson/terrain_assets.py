from __future__ import annotations


_TERRAIN_TEXTURES: dict[int, tuple[str, str]] = {
    0: ("ter_q1_base", "ter/ter_q1_base.jaz"),
    1: ("ter_q1_tex1", "ter/ter_q1_tex1.jaz"),
    2: ("ter_q2_base", "ter/ter_q2_base.jaz"),
    3: ("ter_q2_tex1", "ter/ter_q2_tex1.jaz"),
    4: ("ter_q3_base", "ter/ter_q3_base.jaz"),
    5: ("ter_q3_tex1", "ter/ter_q3_tex1.jaz"),
    6: ("ter_q4_base", "ter/ter_q4_base.jaz"),
    7: ("ter_q4_tex1", "ter/ter_q4_tex1.jaz"),
}


def terrain_texture_by_id(terrain_id: int) -> tuple[str, str] | None:
    """Return (texture_cache_key, paq_relative_path) for a terrain texture ID."""
    return _TERRAIN_TEXTURES.get(int(terrain_id))

