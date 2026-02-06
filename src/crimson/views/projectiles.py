from __future__ import annotations

from dataclasses import dataclass

import pyray as rl

from ._ui_helpers import draw_ui_text, ui_line_height
from .registry import register_view
from grim.fonts.small import SmallFontData, load_small_font
from grim.view import View, ViewContext
from grim.geom import Vec2

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)
UI_KNOWN_COLOR = rl.Color(80, 160, 240, 255)
UI_HOVER_COLOR = rl.Color(240, 200, 80, 255)


@dataclass(frozen=True, slots=True)
class KnownProjectile:
    type_id: int
    grid: int
    frame: int
    label: str


KNOWN_PROJECTILES = [
    KnownProjectile(type_id=0x13, grid=2, frame=0, label="Pulse Gun"),
    KnownProjectile(type_id=0x1D, grid=4, frame=3, label="Splitter Gun"),
    KnownProjectile(type_id=0x19, grid=4, frame=6, label="Blade Gun"),
    KnownProjectile(type_id=0x15, grid=4, frame=2, label="Ion Rifle"),
    KnownProjectile(type_id=0x16, grid=4, frame=2, label="Ion Minigun"),
    KnownProjectile(type_id=0x17, grid=4, frame=2, label="Ion Cannon"),
    KnownProjectile(type_id=0x18, grid=4, frame=2, label="Shrinkifier 5k"),
    KnownProjectile(type_id=0x2D, grid=4, frame=2, label="Fire Bullets"),
]


def _build_known_map() -> dict[int, dict[int, list[KnownProjectile]]]:
    known: dict[int, dict[int, list[KnownProjectile]]] = {}
    for entry in KNOWN_PROJECTILES:
        grid_map = known.setdefault(entry.grid, {})
        grid_map.setdefault(entry.frame, []).append(entry)
    return known


KNOWN_BY_GRID = _build_known_map()


class ProjectileView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._texture: rl.Texture | None = None
        self._small: SmallFontData | None = None
        self._grid = 4

    def open(self) -> None:
        self._missing_assets.clear()
        self._small = load_small_font(self._assets_root, self._missing_assets)
        path = self._assets_root / "crimson" / "game" / "projs.png"
        if not path.is_file():
            self._missing_assets.append("game/projs.png")
            raise FileNotFoundError(f"Missing asset: {path}")
        self._texture = rl.load_texture(str(path))

    def close(self) -> None:
        if self._texture is not None:
            rl.unload_texture(self._texture)
            self._texture = None
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None

    def update(self, dt: float) -> None:
        del dt

    def _handle_input(self) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_TWO):
            self._grid = 2
        if rl.is_key_pressed(rl.KeyboardKey.KEY_FOUR):
            self._grid = 4
        if rl.is_key_pressed(rl.KeyboardKey.KEY_G):
            self._grid = 2 if self._grid == 4 else 4

    def draw(self) -> None:
        rl.clear_background(rl.Color(12, 12, 14, 255))
        if self._missing_assets:
            message = "Missing assets: " + ", ".join(self._missing_assets)
            draw_ui_text(self._small, message, Vec2(24, 24), scale=UI_TEXT_SCALE, color=UI_ERROR_COLOR)
            return
        if self._texture is None:
            draw_ui_text(
                self._small, "No projectile texture loaded.", Vec2(24, 24), scale=UI_TEXT_SCALE, color=UI_TEXT_COLOR
            )
            return

        self._handle_input()

        margin = 24
        panel_gap = 32
        panel_width = min(360, int(rl.get_screen_width() * 0.35))
        available_width = rl.get_screen_width() - margin * 2 - panel_gap - panel_width
        available_height = rl.get_screen_height() - margin * 2 - 60
        scale = min(
            2.0,
            available_width / self._texture.width,
            available_height / self._texture.height,
        )
        draw_w = self._texture.width * scale
        draw_h = self._texture.height * scale
        x = margin
        y = margin + 60

        src = rl.Rectangle(0.0, 0.0, float(self._texture.width), float(self._texture.height))
        dst = rl.Rectangle(float(x), float(y), float(draw_w), float(draw_h))
        rl.draw_texture_pro(self._texture, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        cell_w = draw_w / self._grid
        cell_h = draw_h / self._grid
        for i in range(1, self._grid):
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

        known_frames = KNOWN_BY_GRID.get(self._grid, {})
        for frame_index in known_frames:
            row = frame_index // self._grid
            col = frame_index % self._grid
            hl = rl.Rectangle(
                float(x + col * cell_w),
                float(y + row * cell_h),
                float(cell_w),
                float(cell_h),
            )
            rl.draw_rectangle_lines_ex(hl, 2, UI_KNOWN_COLOR)

        hovered_index = None
        mouse = rl.get_mouse_position()
        if x <= mouse.x <= x + draw_w and y <= mouse.y <= y + draw_h:
            col = int((mouse.x - x) // cell_w)
            row = int((mouse.y - y) // cell_h)
            if 0 <= col < self._grid and 0 <= row < self._grid:
                hovered_index = row * self._grid + col
                hl = rl.Rectangle(
                    float(x + col * cell_w),
                    float(y + row * cell_h),
                    float(cell_w),
                    float(cell_h),
                )
                rl.draw_rectangle_lines_ex(hl, 3, UI_HOVER_COLOR)

        info_x = x + draw_w + panel_gap
        info_y = margin
        draw_ui_text(
            self._small,
            f"projs.png (grid {self._grid}x{self._grid})",
            Vec2(info_x, info_y),
            scale=UI_TEXT_SCALE,
            color=UI_TEXT_COLOR,
        )
        info_y += ui_line_height(self._small, scale=UI_TEXT_SCALE) + 6
        draw_ui_text(
            self._small, "2/4: grid  G: toggle", Vec2(info_x, info_y), scale=UI_TEXT_SCALE, color=UI_HINT_COLOR
        )
        info_y += ui_line_height(self._small, scale=UI_TEXT_SCALE) + 12

        if hovered_index is not None:
            draw_ui_text(
                self._small,
                f"frame {hovered_index:02d}",
                Vec2(info_x, info_y),
                scale=UI_TEXT_SCALE,
                color=UI_TEXT_COLOR,
            )
            info_y += ui_line_height(self._small, scale=UI_TEXT_SCALE) + 6
            entries = known_frames.get(hovered_index, [])
            if entries:
                for entry in entries:
                    draw_ui_text(
                        self._small,
                        f"0x{entry.type_id:02x} {entry.label}",
                        Vec2(info_x, info_y),
                        scale=UI_TEXT_SCALE,
                        color=UI_TEXT_COLOR,
                    )
                    info_y += ui_line_height(self._small, scale=UI_TEXT_SCALE) + 4
            else:
                draw_ui_text(
                    self._small, "no known mapping", Vec2(info_x, info_y), scale=UI_TEXT_SCALE, color=UI_HINT_COLOR
                )
                info_y += ui_line_height(self._small, scale=UI_TEXT_SCALE) + 4
            info_y += 8

        draw_ui_text(self._small, "Known frames", Vec2(info_x, info_y), scale=UI_TEXT_SCALE, color=UI_TEXT_COLOR)
        info_y += ui_line_height(self._small, scale=UI_TEXT_SCALE) + 6
        for frame_index in sorted(known_frames.keys()):
            entries = known_frames[frame_index]
            labels = ", ".join(f"0x{entry.type_id:02x} {entry.label}" for entry in entries)
            draw_ui_text(
                self._small,
                f"{frame_index:02d}: {labels}",
                Vec2(info_x, info_y),
                scale=UI_TEXT_SCALE,
                color=UI_HINT_COLOR,
            )
            info_y += ui_line_height(self._small, scale=UI_TEXT_SCALE) + 4


@register_view("projectiles", "Projectile atlas preview")
def build_projectile_view(ctx: ViewContext) -> View:
    return ProjectileView(ctx)
