from __future__ import annotations

from grim.geom import SupportsXY, Vec2


def mouse_inside_rect_with_padding(
    mouse: SupportsXY,
    *,
    pos: Vec2,
    width: float,
    height: float,
    left_pad: float = 10.0,
    top_pad: float = 2.0,
) -> bool:
    """Port of `ui_mouse_inside_rect_with_padding` (0x00403430)."""

    x = float(pos.x)
    y = float(pos.y)
    return (
        x - float(left_pad) <= float(mouse.x) <= x + float(width)
        and y - float(top_pad) <= float(mouse.y) <= y + float(height)
    )
