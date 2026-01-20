from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pyray as rl

from ..font import DEFAULT_SAMPLE
from .registry import register_view
from .types import View, ViewContext


@dataclass(frozen=True, slots=True)
class SmallFontData:
    widths: list[int]
    texture: rl.Texture
    cell_size: int = 16
    grid: int = 16


@dataclass(frozen=True, slots=True)
class MonoFontData:
    texture: rl.Texture
    grid: int = 16
    cell_width: float = 16.0
    cell_height: float = 16.0
    advance: float = 16.0


class FontView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None
        self._mono: MonoFontData | None = None
        self._sample = DEFAULT_SAMPLE

    def _load_small_font(self, assets_root: Path) -> SmallFontData | None:
        widths_path = assets_root / "crimson" / "load" / "smallFnt.dat"
        atlas_path = assets_root / "crimson" / "load" / "smallWhite.png"
        if not widths_path.is_file() or not atlas_path.is_file():
            self._missing_assets.append("small font assets")
            return None
        widths = list(widths_path.read_bytes())
        texture = rl.load_texture(str(atlas_path))
        return SmallFontData(widths=widths, texture=texture)

    def _load_mono_font(self, assets_root: Path) -> MonoFontData | None:
        atlas_path = assets_root / "crimson" / "load" / "default_font_courier.png"
        if not atlas_path.is_file():
            self._missing_assets.append("default_font_courier.png")
            return None
        texture = rl.load_texture(str(atlas_path))
        grid = 16
        cell_width = texture.width / grid
        cell_height = texture.height / grid
        return MonoFontData(
            texture=texture,
            grid=grid,
            cell_width=cell_width,
            cell_height=cell_height,
            advance=16.0,
        )

    def close(self) -> None:
        if self._small is not None:
            rl.unload_texture(self._small.texture)
        if self._mono is not None:
            rl.unload_texture(self._mono.texture)

    def open(self) -> None:
        self._missing_assets.clear()
        self._small = self._load_small_font(self._assets_root)
        self._mono = self._load_mono_font(self._assets_root)

    def update(self, dt: float) -> None:
        del dt

    def draw(self) -> None:
        rl.clear_background(rl.Color(12, 12, 14, 255))
        if self._missing_assets:
            message = "Missing assets: " + ", ".join(self._missing_assets)
            rl.draw_text(message, 24, 24, 20, rl.Color(240, 80, 80, 255))
            return
        y = 24
        rl.draw_text("Small font", 24, y, 20, rl.Color(220, 220, 220, 255))
        y += 28
        if self._small is not None:
            self._draw_small_text(self._sample, 24, y, 1.5, rl.WHITE)
            y += int(self._small.cell_size * 1.5 * (self._sample.count("\n") + 1)) + 40

        rl.draw_text("Mono font", 24, y, 20, rl.Color(220, 220, 220, 255))
        y += 28
        if self._mono is not None:
            self._draw_mono_text(self._sample, 24, y, 1.0, rl.WHITE)

    def _draw_small_text(self, text: str, x: float, y: float, scale: float, color: rl.Color) -> None:
        if self._small is None:
            return
        font = self._small
        x_pos = x
        y_pos = y
        line_height = font.cell_size * scale
        origin = rl.Vector2(0.0, 0.0)
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
            src = rl.Rectangle(
                float(col * font.cell_size),
                float(row * font.cell_size),
                float(width),
                float(font.cell_size),
            )
            dst = rl.Rectangle(
                float(x_pos),
                float(y_pos),
                float(width * scale),
                float(font.cell_size * scale),
            )
            rl.draw_texture_pro(font.texture, src, dst, origin, 0.0, color)
            x_pos += width * scale

    def _draw_mono_text(self, text: str, x: float, y: float, scale: float, color: rl.Color) -> None:
        if self._mono is None:
            return
        font = self._mono
        x_pos = x
        y_pos = y
        line_height = font.advance * scale
        origin = rl.Vector2(0.0, 0.0)
        for value in text.encode("latin-1", errors="replace"):
            if value == 0x0A:
                x_pos = x
                y_pos += line_height
                continue
            if value == 0x0D:
                continue
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
                float(y_pos),
                float(font.advance * scale),
                float(font.advance * scale),
            )
            rl.draw_texture_pro(font.texture, src, dst, origin, 0.0, color)
            x_pos += font.advance * scale


@register_view("fonts", "Font preview")
def build_font_view(ctx: ViewContext) -> View:
    return FontView(ctx)
