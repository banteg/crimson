from __future__ import annotations

from grim.raylib_api import rl

from ...effects_atlas import effect_src_rect


def effect_cell_src(texture: rl.Texture, effect_id: int) -> rl.Rectangle | None:
    """`effect_select_texture`: the effect's whole atlas cell (`grim_set_atlas_frame`)."""
    cell = effect_src_rect(effect_id, texture_width=float(texture.width), texture_height=float(texture.height))
    return None if cell is None else rl.Rectangle(*cell)


def effect_cell_src_inset(texture: rl.Texture, effect_id: int) -> rl.Rectangle | None:
    """The effect's atlas cell inset by 2 px: port-only, so bilinear filtering does not bleed in neighbouring frames."""
    cell = effect_src_rect(effect_id, texture_width=float(texture.width), texture_height=float(texture.height))
    if cell is None:
        return None
    x, y, w, h = cell
    return rl.Rectangle(x, y, max(0.0, w - 2.0), max(0.0, h - 2.0))
