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


SMALL_FONT_UV_BIAS_PX = 0.5
SMALL_FONT_FILTER = rl.TextureFilter.TEXTURE_FILTER_POINT
SMALL_FONT_RENDER_SCALE = 1.0


def load_small_font(assets_root: Path) -> SmallFontData:
    return runtime_resources_for(assets_root).small_font


def draw_small_text(font: SmallFontData, text: str, pos: Vec2, scale: float, color: rl.Color) -> None:
    x_pos = pos.x
    y_pos = pos.y
    scale_px = scale * SMALL_FONT_RENDER_SCALE
    line_height = font.cell_size * scale_px
    snap = abs(scale_px - round(scale_px)) < 0.001
    if snap:
        scale_px = float(round(scale_px))
    origin = rl.Vector2(0.0, 0.0)
    bias = 0.0 if SMALL_FONT_FILTER == rl.TextureFilter.TEXTURE_FILTER_POINT else SMALL_FONT_UV_BIAS_PX
    for value in text.encode("latin-1", errors="replace"):
        if value == 0x0A:
            x_pos = pos.x
            y_pos += line_height
            continue
        if value == 0x0D:
            continue
        width = font.widths[value]
        if width <= 0:
            continue
        col = value % font.grid
        row = value // font.grid
        src_w = max(float(width) - bias, 0.5)
        src_h = max(float(font.cell_size) - bias, 0.5)
        src = rl.Rectangle(
            float(col * font.cell_size) + bias,
            float(row * font.cell_size) + bias,
            src_w,
            src_h,
        )
        dst_x = float(round(x_pos)) if snap else float(x_pos)
        dst_y = float(round(y_pos)) if snap else float(y_pos)
        dst_w = float(round(width * scale_px)) if snap else float(width * scale_px)
        dst_h = float(round(font.cell_size * scale_px)) if snap else float(font.cell_size * scale_px)
        dst = rl.Rectangle(
            dst_x,
            dst_y,
            dst_w,
            dst_h,
        )
        rl.draw_texture_pro(font.texture, src, dst, origin, 0.0, color)
        x_pos += width * scale_px


def measure_small_text_height(font: SmallFontData, text: str, scale: float) -> float:
    line_count = text.count("\n") + 1
    scale_px = scale * SMALL_FONT_RENDER_SCALE
    return font.cell_size * scale_px * line_count


def measure_small_text_width(font: SmallFontData, text: str, scale: float) -> float:
    """Return the maximum line width for `text` when rendered with `draw_small_text`."""
    scale_px = scale * SMALL_FONT_RENDER_SCALE
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
        x += float(width) * scale_px
    best = max(best, x)
    return best
