from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pyray as rl

from grim.assets import PaqTextureCache, load_paq_entries


@dataclass(frozen=True, slots=True)
class SmallFontData:
    widths: list[int]
    texture: rl.Texture
    cell_size: int = 16
    grid: int = 16


SMALL_FONT_UV_BIAS_PX = 0.5
SMALL_FONT_FILTER = rl.TEXTURE_FILTER_BILINEAR


def load_small_font(assets_root: Path, missing_assets: list[str]) -> SmallFontData:
    # Prefer crimson.paq (runtime source-of-truth), but fall back to extracted
    # assets when present for development convenience.
    paq_path = assets_root / "crimson.paq"
    if paq_path.is_file():
        try:
            entries = load_paq_entries(assets_root)
            widths_data = entries.get("load/smallFnt.dat")
            if widths_data is not None:
                cache = PaqTextureCache(entries=entries, textures={})
                texture_asset = cache.get_or_load("smallWhite", "load/smallWhite.tga")
                if texture_asset.texture is not None:
                    rl.set_texture_filter(texture_asset.texture, SMALL_FONT_FILTER)
                    return SmallFontData(widths=list(widths_data), texture=texture_asset.texture)
        except Exception:
            pass

    widths_path = assets_root / "crimson" / "load" / "smallFnt.dat"
    atlas_png = assets_root / "crimson" / "load" / "smallWhite.png"
    atlas_tga = assets_root / "crimson" / "load" / "smallWhite.tga"
    if not widths_path.is_file() or (not atlas_png.is_file() and not atlas_tga.is_file()):
        missing_assets.append("small font assets")
        raise FileNotFoundError(f"Missing small font assets: {widths_path} and {atlas_png} or {atlas_tga}")
    widths = list(widths_path.read_bytes())
    texture = rl.load_texture(str(atlas_png if atlas_png.is_file() else atlas_tga))
    rl.set_texture_filter(texture, SMALL_FONT_FILTER)
    return SmallFontData(widths=widths, texture=texture)


def draw_small_text(font: SmallFontData, text: str, x: float, y: float, scale: float, color: rl.Color) -> None:
    x_pos = x
    y_pos = y
    line_height = font.cell_size * scale
    origin = rl.Vector2(0.0, 0.0)
    bias = SMALL_FONT_UV_BIAS_PX
    for value in text.encode("latin-1", errors="replace"):
        if value == 0x0A:
            x_pos = x
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
        dst = rl.Rectangle(
            float(x_pos),
            float(y_pos),
            float(width * scale),
            float(font.cell_size * scale),
        )
        rl.draw_texture_pro(font.texture, src, dst, origin, 0.0, color)
        x_pos += width * scale


def measure_small_text_height(font: SmallFontData, text: str, scale: float) -> float:
    line_count = text.count("\n") + 1
    return font.cell_size * scale * line_count
