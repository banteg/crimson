from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pyray as rl


@dataclass(frozen=True, slots=True)
class SmallFontData:
    widths: list[int]
    texture: rl.Texture
    cell_size: int = 16
    grid: int = 16


def load_small_font(assets_root: Path, missing_assets: list[str]) -> SmallFontData | None:
    widths_path = assets_root / "crimson" / "load" / "smallFnt.dat"
    atlas_path = assets_root / "crimson" / "load" / "smallWhite.png"
    if not widths_path.is_file() or not atlas_path.is_file():
        missing_assets.append("small font assets")
        return None
    widths = list(widths_path.read_bytes())
    texture = rl.load_texture(str(atlas_path))
    return SmallFontData(widths=widths, texture=texture)


def draw_small_text(
    font: SmallFontData, text: str, x: float, y: float, scale: float, color: rl.Color
) -> None:
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


def measure_small_text_height(font: SmallFontData, text: str, scale: float) -> float:
    line_count = text.count("\n") + 1
    return font.cell_size * scale * line_count
