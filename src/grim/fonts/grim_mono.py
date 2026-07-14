from __future__ import annotations

from pathlib import Path

import msgspec

from grim.assets import TextureId, runtime_resources_for
from grim.geom import Vec2
from grim.raylib_api import rl

GRIM_MONO_ADVANCE = 16.0
GRIM_MONO_DRAW_SIZE = 32.0
GRIM_MONO_LINE_HEIGHT = 28.0
GRIM_MONO_TEXTURE_FILTER = rl.TextureFilter.TEXTURE_FILTER_BILINEAR


class GrimMonoFont(msgspec.Struct, frozen=True):
    texture: rl.Texture
    grid: int = 16
    cell_width: float = 16.0
    cell_height: float = 16.0
    advance: float = GRIM_MONO_ADVANCE


def _draw_mono_glyph(
    font: GrimMonoFont,
    value: int,
    x_pos: float,
    y_pos: float,
    draw_size: float,
    origin: rl.Vector2,
    color: rl.Color,
) -> None:
    col = value % font.grid
    row = value // font.grid
    src = rl.Rectangle(
        float(col * font.cell_width),
        float(row * font.cell_height),
        float(font.cell_width),
        float(font.cell_height),
    )
    dst = rl.Rectangle(x_pos, y_pos, draw_size, draw_size)
    rl.draw_texture_pro(font.texture, src, dst, origin, 0.0, color)


def load_grim_mono_font(assets_root: Path) -> GrimMonoFont:
    texture = runtime_resources_for(assets_root).texture(TextureId.DEFAULT_FONT_COURIER)
    rl.set_texture_filter(texture, GRIM_MONO_TEXTURE_FILTER)
    grid = 16
    cell_width = texture.width / grid
    cell_height = texture.height / grid
    return GrimMonoFont(
        texture=texture,
        grid=grid,
        cell_width=cell_width,
        cell_height=cell_height,
        advance=GRIM_MONO_ADVANCE,
    )


def draw_grim_mono_text(font: GrimMonoFont, text: str, pos: Vec2, scale: float, color: rl.Color) -> None:
    x_pos = pos.x
    y_pos = pos.y
    advance = font.advance * scale
    draw_size = GRIM_MONO_DRAW_SIZE * scale
    line_height = GRIM_MONO_LINE_HEIGHT * scale
    origin = rl.Vector2(0.0, 0.0)
    skip_advance = False
    for value in text.encode("latin-1", errors="replace"):
        if value == 0x0A:
            x_pos = pos.x
            y_pos += line_height
            continue
        if value == 0x0D:
            continue
        if value == 0xA7:
            skip_advance = True
            continue

        if value == 0xE5:
            x_pos += advance
            _draw_mono_glyph(font, ord("a"), x_pos, y_pos + 1.0, draw_size, origin, color)
            _draw_mono_glyph(font, ord("."), x_pos, y_pos - 6.0, draw_size, origin, color)
            continue
        if value == 0xE4:
            x_pos += advance
            _draw_mono_glyph(font, ord("a"), x_pos, y_pos + 1.0, draw_size, origin, color)
            _draw_mono_glyph(font, ord('"'), x_pos, y_pos, draw_size, origin, color)
            continue
        if value == 0xF6:
            x_pos += advance
            _draw_mono_glyph(font, ord("o"), x_pos, y_pos + 1.0, draw_size, origin, color)
            _draw_mono_glyph(font, ord('"'), x_pos, y_pos, draw_size, origin, color)
            continue

        if skip_advance:
            skip_advance = False
        else:
            x_pos += advance

        _draw_mono_glyph(font, value, x_pos, y_pos + 1.0, draw_size, origin, color)


def measure_grim_mono_text_height(font: GrimMonoFont, text: str, scale: float) -> float:
    line_count = text.count("\n") + 1
    return GRIM_MONO_LINE_HEIGHT * scale * line_count
