from __future__ import annotations

from grim.geom import Vec2
from grim.raylib_api import rl, rl_rectangle


def grim_draw_rect_outline(xy: Vec2, width: float, height: float, color: rl.Color) -> None:
    """`grim_draw_rect_outline`: one quad for a 1px side, else four 1px quads with the bottom one a pixel wider."""
    if height == 1.0:
        quads = ((xy.x, xy.y, width, 1.0),)
    elif width == 1.0:
        quads = ((xy.x, xy.y, 1.0, height),)
    else:
        quads = (
            (xy.x, xy.y, width, 1.0),
            (xy.x, xy.y, 1.0, height),
            (xy.x, xy.y + height, width + 1.0, 1.0),
            (xy.x + width, xy.y, 1.0, height),
        )
    for x, y, w, h in quads:
        rl.draw_rectangle_rec(rl_rectangle(x, y, w, h), color)
