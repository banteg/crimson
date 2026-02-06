from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pyray as rl

from grim.assets import PaqTextureCache, find_paq_path, load_paq_entries_from_path
from grim.geom import Vec2

GRIM_MONO_ADVANCE = 16.0
GRIM_MONO_DRAW_SIZE = 32.0
GRIM_MONO_LINE_HEIGHT = 28.0
GRIM_MONO_TEXTURE_FILTER = rl.TextureFilter.TEXTURE_FILTER_BILINEAR


@dataclass(frozen=True, slots=True)
class GrimMonoFont:
    texture: rl.Texture
    grid: int = 16
    cell_width: float = 16.0
    cell_height: float = 16.0
    advance: float = GRIM_MONO_ADVANCE


def load_grim_mono_font(assets_root: Path, missing_assets: list[str]) -> GrimMonoFont:
    # Prefer crimson.paq (runtime source-of-truth), but fall back to extracted
    # assets when present for development convenience.
    paq_path = find_paq_path(assets_root)

    atlas_png = assets_root / "crimson" / "load" / "default_font_courier.png"
    atlas_tga = assets_root / "crimson" / "load" / "default_font_courier.tga"

    texture: rl.Texture | None = None
    if paq_path is not None:
        try:
            entries = load_paq_entries_from_path(paq_path)
            cache = PaqTextureCache(entries=entries, textures={})
            texture_asset = cache.get_or_load("default_font_courier", "load/default_font_courier.tga")
            texture = texture_asset.texture
        except Exception:
            texture = None

    if texture is None:
        if atlas_png.is_file():
            texture = rl.load_texture(str(atlas_png))
        elif atlas_tga.is_file():
            texture = rl.load_texture(str(atlas_tga))
        else:
            missing_assets.append("load/default_font_courier.tga")
            raise FileNotFoundError(
                "Missing grim mono font (expected load/default_font_courier.tga in crimson.paq "
                "or extracted crimson/load/default_font_courier.(png|tga))"
            )

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

        if skip_advance:
            skip_advance = False
        else:
            x_pos += advance

        col = value % font.grid
        row = value // font.grid
        src = rl.Rectangle(
            float(col * font.cell_width),
            float(row * font.cell_height),
            float(font.cell_width),
            float(font.cell_height),
        )
        dst = rl.Rectangle(
            float(x_pos),
            float(y_pos + 1.0),
            float(draw_size),
            float(draw_size),
        )
        rl.draw_texture_pro(font.texture, src, dst, origin, 0.0, color)


def measure_grim_mono_text_height(font: GrimMonoFont, text: str, scale: float) -> float:
    line_count = text.count("\n") + 1
    return GRIM_MONO_LINE_HEIGHT * scale * line_count
