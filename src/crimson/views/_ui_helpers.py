from __future__ import annotations

import pyray as rl

from grim.fonts.small import SmallFontData, draw_small_text


def ui_line_height(font: SmallFontData | None, *, scale: float = 1.0) -> int:
    if font is not None:
        return int(font.cell_size * float(scale))
    return int(20 * float(scale))


def draw_ui_text(
    font: SmallFontData | None,
    text: str,
    x: float,
    y: float,
    *,
    color: rl.Color,
    scale: float = 1.0,
) -> None:
    if font is not None:
        draw_small_text(font, text, x, y, float(scale), color)
    else:
        rl.draw_text(text, int(x), int(y), int(20 * float(scale)), color)

