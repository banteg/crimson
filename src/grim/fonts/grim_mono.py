from __future__ import annotations

from pathlib import Path

import msgspec
from construct import ConstructError

from grim.assets import PaqTextureCache, find_paq_path, load_paq_entries_from_path, preloaded_paq_resources
from grim.geom import Vec2
from grim.raylib_api import rl

GRIM_MONO_ADVANCE = 16.0
GRIM_MONO_DRAW_SIZE = 32.0
GRIM_MONO_LINE_HEIGHT = 28.0
GRIM_MONO_TEXTURE_FILTER = rl.TextureFilter.TEXTURE_FILTER_BILINEAR


class GrimMonoFont(msgspec.Struct, frozen=True):
    texture: rl.Texture
    shared: bool = False
    grid: int = 16
    cell_width: float = 16.0
    cell_height: float = 16.0
    advance: float = GRIM_MONO_ADVANCE


_SHARED_GRIM_MONO_FONTS: dict[Path, GrimMonoFont] = {}


def _assets_root_key(assets_root: Path) -> Path:
    return assets_root.resolve()


def _load_grim_mono_from_shared_paq(assets_root: Path) -> GrimMonoFont | None:
    shared = preloaded_paq_resources(assets_root)
    if shared is None:
        return None
    texture_asset = shared.resource_paq.texture_cache.get_or_load(
        "default_font_courier",
        "load/default_font_courier.tga",
    )
    texture = texture_asset.texture
    if texture is None:
        raise FileNotFoundError("Missing grim mono font atlas in resource PAQ: load/default_font_courier.tga")
    rl.set_texture_filter(texture, GRIM_MONO_TEXTURE_FILTER)
    grid = 16
    cell_width = texture.width / grid
    cell_height = texture.height / grid
    return GrimMonoFont(
        texture=texture,
        shared=True,
        grid=grid,
        cell_width=cell_width,
        cell_height=cell_height,
        advance=GRIM_MONO_ADVANCE,
    )


def preload_grim_mono_font(assets_root: Path) -> GrimMonoFont:
    key = _assets_root_key(assets_root)
    existing = _SHARED_GRIM_MONO_FONTS.get(key)
    if existing is not None:
        return existing
    font = _load_grim_mono_from_shared_paq(assets_root)
    if font is None:
        raise FileNotFoundError(f"Shared grim mono font requires preloaded PAQ resources: {assets_root}")
    _SHARED_GRIM_MONO_FONTS[key] = font
    return font


def clear_preloaded_grim_mono_font(assets_root: Path) -> None:
    _SHARED_GRIM_MONO_FONTS.pop(_assets_root_key(assets_root), None)


def unload_grim_mono_font(font: GrimMonoFont | None) -> None:
    if font is None or bool(getattr(font, "shared", False)):
        return
    texture = getattr(font, "texture", None)
    if texture is None:
        return
    rl.unload_texture(texture)


def load_grim_mono_font(assets_root: Path) -> GrimMonoFont:
    shared = _SHARED_GRIM_MONO_FONTS.get(_assets_root_key(assets_root))
    if shared is not None:
        return shared
    preloaded = _load_grim_mono_from_shared_paq(assets_root)
    if preloaded is not None:
        _SHARED_GRIM_MONO_FONTS[_assets_root_key(assets_root)] = preloaded
        return preloaded
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
        except (ConstructError, FileNotFoundError, OSError, ValueError, RuntimeError):
            texture = None

    if texture is None:
        if atlas_png.is_file():
            texture = rl.load_texture(str(atlas_png))
        elif atlas_tga.is_file():
            texture = rl.load_texture(str(atlas_tga))
        else:
            raise FileNotFoundError(
                "Missing grim mono font (expected load/default_font_courier.tga in crimson.paq "
                "or extracted crimson/load/default_font_courier.(png|tga))",
            )

    rl.set_texture_filter(texture, GRIM_MONO_TEXTURE_FILTER)
    grid = 16
    cell_width = texture.width / grid
    cell_height = texture.height / grid
    return GrimMonoFont(
        texture=texture,
        shared=False,
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
