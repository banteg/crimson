from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pyray as rl

GRIM_MONO_ADVANCE = 16.0
GRIM_MONO_DRAW_SIZE = 32.0
GRIM_MONO_LINE_HEIGHT = 28.0


@dataclass(frozen=True, slots=True)
class GrimMonoFont:
    texture: rl.Texture
    grid: int = 16
    cell_width: float = 16.0
    cell_height: float = 16.0
    advance: float = GRIM_MONO_ADVANCE


def load_grim_mono_font(
    assets_root: Path, missing_assets: list[str]
) -> GrimMonoFont | None:
    atlas_path = assets_root / "crimson" / "load" / "default_font_courier.png"
    if not atlas_path.is_file():
        missing_assets.append("default_font_courier.png")
        return None
    texture = rl.load_texture(str(atlas_path))
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


def draw_grim_mono_text(
    font: GrimMonoFont, text: str, x: float, y: float, scale: float, color: rl.Color
) -> None:
    x_pos = x
    y_pos = y
    line_height = GRIM_MONO_LINE_HEIGHT * scale
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
            float(GRIM_MONO_DRAW_SIZE * scale),
            float(GRIM_MONO_DRAW_SIZE * scale),
        )
        rl.draw_texture_pro(font.texture, src, dst, origin, 0.0, color)
        x_pos += font.advance * scale


def measure_grim_mono_text_height(font: GrimMonoFont, text: str, scale: float) -> float:
    line_count = text.count("\n") + 1
    return GRIM_MONO_LINE_HEIGHT * scale * line_count
