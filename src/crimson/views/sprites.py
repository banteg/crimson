from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pyray as rl

from .registry import register_view
from .types import View, ViewContext


@dataclass(frozen=True, slots=True)
class SpriteSheetSpec:
    name: str
    rel_path: str
    grids: tuple[int, ...]


@dataclass(slots=True)
class SpriteSheet:
    name: str
    texture: rl.Texture
    grids: tuple[int, ...]
    grid_index: int = 0

    @property
    def grid(self) -> int:
        return self.grids[self.grid_index]


SPRITE_SHEETS: list[SpriteSheetSpec] = [
    SpriteSheetSpec("projs", "game/projs.png", (4, 2)),
    SpriteSheetSpec("particles", "game/particles.png", (8, 4)),
    SpriteSheetSpec("bonuses", "game/bonuses.png", (4,)),
    SpriteSheetSpec("bodyset", "game/bodyset.png", (8,)),
    SpriteSheetSpec("muzzleFlash", "game/muzzleFlash.png", (4, 2)),
    SpriteSheetSpec("arrow", "game/arrow.png", (1,)),
]


class SpriteSheetView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._sheets: list[SpriteSheet] = []
        self._index = 0

    def open(self) -> None:
        self._missing_assets.clear()
        self._sheets.clear()
        for spec in SPRITE_SHEETS:
            path = self._assets_root / "crimson" / spec.rel_path
            if not path.is_file():
                self._missing_assets.append(spec.rel_path)
                continue
            texture = rl.load_texture(str(path))
            self._sheets.append(
                SpriteSheet(name=spec.name, texture=texture, grids=spec.grids)
            )

    def close(self) -> None:
        for sheet in self._sheets:
            rl.unload_texture(sheet.texture)
        self._sheets.clear()

    def update(self, dt: float) -> None:
        del dt

    def _advance_sheet(self, delta: int) -> None:
        if not self._sheets:
            return
        self._index = (self._index + delta) % len(self._sheets)

    def _set_grid(self, grid: int) -> None:
        if not self._sheets:
            return
        sheet = self._sheets[self._index]
        if grid not in sheet.grids:
            return
        sheet.grid_index = sheet.grids.index(grid)

    def _cycle_grid(self, delta: int) -> None:
        if not self._sheets:
            return
        sheet = self._sheets[self._index]
        sheet.grid_index = (sheet.grid_index + delta) % len(sheet.grids)

    def _handle_input(self) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT):
            self._advance_sheet(1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT):
            self._advance_sheet(-1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_UP):
            self._cycle_grid(1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_DOWN):
            self._cycle_grid(-1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ONE):
            self._set_grid(1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_TWO):
            self._set_grid(2)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_FOUR):
            self._set_grid(4)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_EIGHT):
            self._set_grid(8)

    def draw(self) -> None:
        rl.clear_background(rl.Color(12, 12, 14, 255))
        if self._missing_assets:
            message = "Missing assets: " + ", ".join(self._missing_assets)
            rl.draw_text(message, 24, 24, 20, rl.Color(240, 80, 80, 255))
            return
        if not self._sheets:
            rl.draw_text("No sprite sheets loaded.", 24, 24, 20, rl.WHITE)
            return

        self._handle_input()
        sheet = self._sheets[self._index]
        grid = sheet.grid

        margin = 24
        info = f"{sheet.name} (grid {grid}x{grid})"
        rl.draw_text(info, margin, margin, 22, rl.Color(220, 220, 220, 255))
        hint = "Left/Right: sheet  Up/Down: grid  1/2/4/8: grid"
        rl.draw_text(hint, margin, margin + 28, 16, rl.Color(140, 140, 140, 255))

        available_width = rl.get_screen_width() - margin * 2
        available_height = rl.get_screen_height() - margin * 2 - 60
        scale = min(
            1.0,
            available_width / sheet.texture.width,
            available_height / sheet.texture.height,
        )
        draw_w = sheet.texture.width * scale
        draw_h = sheet.texture.height * scale
        x = margin
        y = margin + 60

        src = rl.Rectangle(0.0, 0.0, float(sheet.texture.width), float(sheet.texture.height))
        dst = rl.Rectangle(float(x), float(y), float(draw_w), float(draw_h))
        rl.draw_texture_pro(sheet.texture, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        if grid > 1:
            cell_w = draw_w / grid
            cell_h = draw_h / grid
            for i in range(1, grid):
                rl.draw_line(
                    int(x + i * cell_w),
                    int(y),
                    int(x + i * cell_w),
                    int(y + draw_h),
                    rl.Color(60, 60, 70, 255),
                )
                rl.draw_line(
                    int(x),
                    int(y + i * cell_h),
                    int(x + draw_w),
                    int(y + i * cell_h),
                    rl.Color(60, 60, 70, 255),
                )

        mouse = rl.get_mouse_position()
        if x <= mouse.x <= x + draw_w and y <= mouse.y <= y + draw_h:
            cell_w = draw_w / grid
            cell_h = draw_h / grid
            col = int((mouse.x - x) // cell_w)
            row = int((mouse.y - y) // cell_h)
            if 0 <= col < grid and 0 <= row < grid:
                index = row * grid + col
                hl = rl.Rectangle(
                    float(x + col * cell_w),
                    float(y + row * cell_h),
                    float(cell_w),
                    float(cell_h),
                )
                rl.draw_rectangle_lines_ex(hl, 2, rl.Color(240, 200, 80, 255))
                rl.draw_text(
                    f"frame {index:02d}",
                    int(x),
                    int(y + draw_h + 10),
                    18,
                    rl.Color(220, 220, 220, 255),
                )


@register_view("sprites", "Sprite atlas preview")
def build_sprite_view(ctx: ViewContext) -> View:
    return SpriteSheetView(ctx)
