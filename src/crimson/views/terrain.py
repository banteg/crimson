from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pyray as rl

from .registry import register_view
from .types import View, ViewContext


@dataclass(frozen=True, slots=True)
class TerrainTexture:
    terrain_id: int
    name: str
    texture: rl.Texture


TERRAIN_TEXTURES: list[tuple[int, str, str]] = [
    (0, "ter_q1_base", "ter/ter_q1_base.png"),
    (1, "ter_q1_tex1", "ter/ter_q1_tex1.png"),
    (2, "ter_q2_base", "ter/ter_q2_base.png"),
    (3, "ter_q2_tex1", "ter/ter_q2_tex1.png"),
    (4, "ter_q3_base", "ter/ter_q3_base.png"),
    (5, "ter_q3_tex1", "ter/ter_q3_tex1.png"),
    (6, "ter_q4_base", "ter/ter_q4_base.png"),
    (7, "ter_q4_tex1", "ter/ter_q4_tex1.png"),
    (8, "fb_q1", "ter/fb_q1.png"),
    (9, "fb_q2", "ter/fb_q2.png"),
    (10, "fb_q3", "ter/fb_q3.png"),
    (11, "fb_q4", "ter/fb_q4.png"),
]


class TerrainView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._textures: list[TerrainTexture] = []

    def open(self) -> None:
        self._missing_assets.clear()
        self._textures.clear()
        for terrain_id, name, rel_path in TERRAIN_TEXTURES:
            path = self._assets_root / "crimson" / rel_path
            if not path.is_file():
                self._missing_assets.append(rel_path)
                continue
            texture = rl.load_texture(str(path))
            self._textures.append(
                TerrainTexture(terrain_id=terrain_id, name=name, texture=texture)
            )

    def close(self) -> None:
        for entry in self._textures:
            rl.unload_texture(entry.texture)
        self._textures.clear()

    def update(self, dt: float) -> None:
        del dt

    def draw(self) -> None:
        rl.clear_background(rl.Color(12, 12, 14, 255))
        if self._missing_assets:
            message = "Missing assets: " + ", ".join(self._missing_assets)
            rl.draw_text(message, 24, 24, 20, rl.Color(240, 80, 80, 255))
            return
        if not self._textures:
            rl.draw_text("No terrain textures loaded.", 24, 24, 20, rl.WHITE)
            return

        cols = 4
        rows = (len(self._textures) + cols - 1) // cols
        margin = 24
        gap_x = 16
        gap_y = 20
        label_height = 18

        cell_w = max(entry.texture.width for entry in self._textures)
        cell_h = max(entry.texture.height for entry in self._textures)
        max_width = rl.get_screen_width() - margin * 2 - gap_x * (cols - 1)
        max_height = rl.get_screen_height() - margin * 2 - gap_y * (rows - 1)
        max_height -= rows * label_height
        scale = min(1.0, max_width / (cols * cell_w), max_height / (rows * cell_h))

        for idx, entry in enumerate(self._textures):
            row = idx // cols
            col = idx % cols
            x = margin + col * (cell_w * scale + gap_x)
            y = margin + row * (cell_h * scale + gap_y + label_height)
            label = f"{entry.terrain_id:02d} {entry.name}"
            rl.draw_text(label, int(x), int(y), 16, rl.Color(220, 220, 220, 255))
            dst = rl.Rectangle(
                float(x),
                float(y + label_height),
                float(entry.texture.width * scale),
                float(entry.texture.height * scale),
            )
            src = rl.Rectangle(0.0, 0.0, float(entry.texture.width), float(entry.texture.height))
            rl.draw_texture_pro(entry.texture, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)


@register_view("terrain", "Terrain textures")
def build_terrain_view(ctx: ViewContext) -> View:
    return TerrainView(ctx)
