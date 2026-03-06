from __future__ import annotations

from pathlib import Path

import msgspec

from grim.assets import PaqTextureCache, find_paq_path, load_paq_entries_from_path, preloaded_paq_resources
from grim.geom import Vec2
from grim.raylib_api import rl


class SmallFontData(msgspec.Struct, frozen=True):
    widths: list[int]
    texture: rl.Texture
    shared: bool = False
    cell_size: int = 16
    grid: int = 16


SMALL_FONT_UV_BIAS_PX = 0.5
SMALL_FONT_FILTER = rl.TextureFilter.TEXTURE_FILTER_POINT
SMALL_FONT_RENDER_SCALE = 1.0
_SHARED_SMALL_FONTS: dict[Path, SmallFontData] = {}


def _assets_root_key(assets_root: Path) -> Path:
    return assets_root.resolve()


def _load_small_font_from_shared_paq(assets_root: Path) -> SmallFontData | None:
    shared = preloaded_paq_resources(assets_root)
    if shared is None:
        return None
    widths_data = shared.resource_paq.entries.get("load/smallFnt.dat")
    if widths_data is None:
        raise FileNotFoundError("Missing small font widths in resource PAQ: load/smallFnt.dat")
    texture_asset = shared.resource_paq.texture_cache.get_or_load("smallWhite", "load/smallWhite.tga")
    texture = texture_asset.texture
    if texture is None:
        raise FileNotFoundError("Missing small font atlas in resource PAQ: load/smallWhite.tga")
    rl.set_texture_filter(texture, SMALL_FONT_FILTER)
    return SmallFontData(widths=list(widths_data), texture=texture, shared=True)


def preload_small_font(assets_root: Path) -> SmallFontData:
    key = _assets_root_key(assets_root)
    existing = _SHARED_SMALL_FONTS.get(key)
    if existing is not None:
        return existing
    font = _load_small_font_from_shared_paq(assets_root)
    if font is None:
        raise FileNotFoundError(f"Shared small font requires preloaded PAQ resources: {assets_root}")
    _SHARED_SMALL_FONTS[key] = font
    return font


def clear_preloaded_small_font(assets_root: Path) -> None:
    _SHARED_SMALL_FONTS.pop(_assets_root_key(assets_root), None)


def unload_small_font(font: SmallFontData | None) -> None:
    if font is None or bool(getattr(font, "shared", False)):
        return
    texture = getattr(font, "texture", None)
    if texture is None:
        return
    rl.unload_texture(texture)


def load_small_font(assets_root: Path) -> SmallFontData:
    shared = _SHARED_SMALL_FONTS.get(_assets_root_key(assets_root))
    if shared is not None:
        return shared
    preloaded = _load_small_font_from_shared_paq(assets_root)
    if preloaded is not None:
        _SHARED_SMALL_FONTS[_assets_root_key(assets_root)] = preloaded
        return preloaded
    # Prefer crimson.paq (runtime source-of-truth), but fall back to extracted
    # assets when present for development convenience.
    paq_path = find_paq_path(assets_root)
    if paq_path is not None:
        try:
            entries = load_paq_entries_from_path(paq_path)
            widths_data = entries.get("load/smallFnt.dat")
            if widths_data is not None:
                cache = PaqTextureCache(entries=entries, textures={})
                texture_asset = cache.get_or_load("smallWhite", "load/smallWhite.tga")
                if texture_asset.texture is not None:
                    rl.set_texture_filter(texture_asset.texture, SMALL_FONT_FILTER)
                    return SmallFontData(widths=list(widths_data), texture=texture_asset.texture, shared=False)
        except (FileNotFoundError, OSError, ValueError):
            # Fall back to extracted assets when PAQ decode/load fails.
            paq_path = None

    widths_path = assets_root / "crimson" / "load" / "smallFnt.dat"
    atlas_png = assets_root / "crimson" / "load" / "smallWhite.png"
    atlas_tga = assets_root / "crimson" / "load" / "smallWhite.tga"
    if not widths_path.is_file() or (not atlas_png.is_file() and not atlas_tga.is_file()):
        raise FileNotFoundError(f"Missing small font assets: {widths_path} and {atlas_png} or {atlas_tga}")
    widths = list(widths_path.read_bytes())
    texture = rl.load_texture(str(atlas_png if atlas_png.is_file() else atlas_tga))
    rl.set_texture_filter(texture, SMALL_FONT_FILTER)
    return SmallFontData(widths=widths, texture=texture, shared=False)


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
