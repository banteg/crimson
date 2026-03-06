from __future__ import annotations

from pathlib import Path

import msgspec

from grim.assets import runtime_resources_for
from grim.geom import Vec2
from grim.raylib_api import rl


class SmallFontData(msgspec.Struct, frozen=True):
    widths: list[int]
    texture: rl.Texture
    cell_size: int = 16
    grid: int = 16


SMALL_FONT_FILTER = rl.TextureFilter.TEXTURE_FILTER_POINT


def load_small_font(assets_root: Path) -> SmallFontData:
    return runtime_resources_for(assets_root).small_font


def draw_small_text(font: SmallFontData, text: str, pos: Vec2, color: rl.Color) -> None:
    x_pos = float(int(pos.x))
    y_pos = float(int(pos.y))
    base_x = x_pos
    line_height = float(font.cell_size)
    origin = rl.Vector2(0.0, 0.0)
    for value in text.encode("latin-1", errors="replace"):
        if value == 0x0A:
            x_pos = base_x
            y_pos += line_height
            continue
        if value == 0x0D:
            continue
        width = font.widths[value]
        if width <= 0:
            continue
        col = value % font.grid
        row = value // font.grid
        # Native Grim2D applies a 1/512 UV inset on the DX8 path. Raylib/OpenGL
        # renders visibly cropped glyphs with that bias, so we intentionally use
        # the full glyph rect here.
        src = rl.Rectangle(
            float(col * font.cell_size),
            float(row * font.cell_size),
            float(width),
            float(font.cell_size),
        )
        dst = rl.Rectangle(
            x_pos,
            y_pos,
            float(width),
            float(font.cell_size),
        )
        rl.draw_texture_pro(font.texture, src, dst, origin, 0.0, color)
        x_pos += float(width)


def measure_small_text_height(font: SmallFontData, text: str) -> float:
    line_count = text.count("\n") + 1
    return float(font.cell_size * line_count)


def measure_small_text_width(font: SmallFontData, text: str) -> float:
    """Return the maximum line width for `text` when rendered with `draw_small_text`."""
    x = 0.0
    best = 0.0
    for value in text.encode("latin-1", errors="replace"):
        if value == 0x0A:
            best = max(best, x)
            x = 0.0
            continue
        if value == 0x0D:
            continue
        width = font.widths[value]
        if width <= 0:
            continue
        x += float(width)
    best = max(best, x)
    return best
