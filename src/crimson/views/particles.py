from __future__ import annotations

from dataclasses import dataclass

import pyray as rl

from ..effects_atlas import EFFECT_ID_ATLAS_TABLE, EffectId, SIZE_CODE_GRID
from ._ui_helpers import draw_ui_text, ui_line_height
from .registry import register_view
from grim.fonts.small import SmallFontData, load_small_font
from grim.view import View, ViewContext

UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)
UI_KNOWN_COLOR = rl.Color(80, 160, 240, 255)
UI_HOVER_COLOR = rl.Color(240, 200, 80, 255)
UI_CLAMP_COLOR = rl.Color(120, 120, 220, 255)

EFFECT_UV_STEP = {
    2: 0.4921875,
    4: 0.2421875,
    8: 0.1171875,
    16: 0.0546875,
}


@dataclass(frozen=True, slots=True)
class EffectEntry:
    effect_id: int
    size_code: int
    frame: int
    label: str | None = None

    @property
    def grid(self) -> int:
        return SIZE_CODE_GRID[self.size_code]


EFFECT_LABELS = {
    EffectId.BURST: "burst",
    EffectId.RING: "ring",
    EffectId.BLOOD_SPLATTER: "blood",
    EffectId.FREEZE_SHARD_0: "freeze",
    EffectId.FREEZE_SHARD_1: "freeze",
    EffectId.FREEZE_SHARD_2: "freeze",
    EffectId.EXPLOSION_BURST: "explosion",
    EffectId.GLOW: "glow",
    EffectId.FREEZE_SHATTER: "shatter",
    EffectId.AURA: "aura",
    EffectId.EXPLOSION_PUFF: "explosion",
    EffectId.CASING: "casing",
}

EFFECT_ENTRIES = [
    EffectEntry(entry.effect_id, entry.size_code, entry.frame, EFFECT_LABELS.get(entry.effect_id))
    for entry in EFFECT_ID_ATLAS_TABLE
]


def _build_effect_map() -> dict[int, dict[int, list[EffectEntry]]]:
    mapping: dict[int, dict[int, list[EffectEntry]]] = {}
    for entry in EFFECT_ENTRIES:
        grid_map = mapping.setdefault(entry.grid, {})
        grid_map.setdefault(entry.frame, []).append(entry)
    return mapping


EFFECT_BY_GRID = _build_effect_map()
GRID_CHOICES = (2, 4, 8, 16)


class ParticleView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._texture: rl.Texture | None = None
        self._small: SmallFontData | None = None
        self._grid = 8
        self._show_uv_clamp = False

    def open(self) -> None:
        self._missing_assets.clear()
        self._small = load_small_font(self._assets_root, self._missing_assets)
        path = self._assets_root / "crimson" / "game" / "particles.png"
        if not path.is_file():
            self._missing_assets.append("game/particles.png")
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

    def _cycle_grid(self, delta: int) -> None:
        idx = GRID_CHOICES.index(self._grid)
        self._grid = GRID_CHOICES[(idx + delta) % len(GRID_CHOICES)]

    def _handle_input(self) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_UP):
            self._cycle_grid(1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_DOWN):
            self._cycle_grid(-1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_TWO):
            self._grid = 2
        if rl.is_key_pressed(rl.KeyboardKey.KEY_FOUR):
            self._grid = 4
        if rl.is_key_pressed(rl.KeyboardKey.KEY_EIGHT):
            self._grid = 8
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ONE):
            self._grid = 16
        if rl.is_key_pressed(rl.KeyboardKey.KEY_U):
            self._show_uv_clamp = not self._show_uv_clamp

    def draw(self) -> None:
        rl.clear_background(rl.Color(12, 12, 14, 255))
        if self._missing_assets:
            message = "Missing assets: " + ", ".join(self._missing_assets)
            draw_ui_text(self._small, message, 24, 24, scale=UI_TEXT_SCALE, color=UI_ERROR_COLOR)
            return
        if self._texture is None:
            draw_ui_text(self._small, "No particles texture loaded.", 24, 24, scale=UI_TEXT_SCALE, color=UI_TEXT_COLOR)
            return

        self._handle_input()

        margin = 24
        panel_gap = 32
        panel_width = min(440, int(rl.get_screen_width() * 0.4))
        available_width = rl.get_screen_width() - margin * 2 - panel_gap - panel_width
        available_height = rl.get_screen_height() - margin * 2 - 60
        scale = min(
            3.0,
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

        grid = self._grid
        cell_w = draw_w / grid
        cell_h = draw_h / grid
        step = EFFECT_UV_STEP.get(grid, 1.0 / grid)
        sample_w = self._texture.width * step * scale
        sample_h = self._texture.height * step * scale
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

        known_frames = EFFECT_BY_GRID.get(grid, {})
        for frame_index in known_frames:
            row = frame_index // grid
            col = frame_index % grid
            hl = rl.Rectangle(
                float(x + col * cell_w),
                float(y + row * cell_h),
                float(cell_w),
                float(cell_h),
            )
            rl.draw_rectangle_lines_ex(hl, 2, UI_KNOWN_COLOR)
            if self._show_uv_clamp:
                inset = rl.Rectangle(
                    float(x + col * cell_w),
                    float(y + row * cell_h),
                    float(sample_w),
                    float(sample_h),
                )
                rl.draw_rectangle_lines_ex(inset, 1, UI_CLAMP_COLOR)

        hovered_index = None
        mouse = rl.get_mouse_position()
        if x <= mouse.x <= x + draw_w and y <= mouse.y <= y + draw_h:
            col = int((mouse.x - x) // cell_w)
            row = int((mouse.y - y) // cell_h)
            if 0 <= col < grid and 0 <= row < grid:
                hovered_index = row * grid + col
                hl = rl.Rectangle(
                    float(x + col * cell_w),
                    float(y + row * cell_h),
                    float(cell_w),
                    float(cell_h),
                )
                rl.draw_rectangle_lines_ex(hl, 3, UI_HOVER_COLOR)
                if self._show_uv_clamp:
                    inset = rl.Rectangle(
                        float(x + col * cell_w),
                        float(y + row * cell_h),
                        float(sample_w),
                        float(sample_h),
                    )
                    rl.draw_rectangle_lines_ex(inset, 1, UI_CLAMP_COLOR)

        info_x = x + draw_w + panel_gap
        info_y = margin
        draw_ui_text(
            self._small,
            f"particles.png (grid {grid}x{grid})",
            info_x,
            info_y,
            scale=UI_TEXT_SCALE,
            color=UI_TEXT_COLOR,
        )
        info_y += ui_line_height(self._small, scale=UI_TEXT_SCALE) + 6
        draw_ui_text(
            self._small,
            "Up/Down: grid  2/4/8: direct  1: grid16  U: UV clamp",
            info_x,
            info_y,
            scale=UI_TEXT_SCALE,
            color=UI_HINT_COLOR,
        )
        info_y += ui_line_height(self._small, scale=UI_TEXT_SCALE) + 12
        if self._show_uv_clamp:
            step_px = int(round(self._texture.width * step))
            draw_ui_text(
                self._small,
                f"UV clamp: {step_px}px of {int(self._texture.width / grid)}px",
                info_x,
                info_y,
                scale=UI_TEXT_SCALE,
                color=UI_HINT_COLOR,
            )
            info_y += ui_line_height(self._small, scale=UI_TEXT_SCALE) + 12

        if hovered_index is not None:
            draw_ui_text(self._small, f"frame {hovered_index:02d}", info_x, info_y, scale=UI_TEXT_SCALE, color=UI_TEXT_COLOR)
            info_y += ui_line_height(self._small, scale=UI_TEXT_SCALE) + 6
            entries = known_frames.get(hovered_index, [])
            if entries:
                for entry in entries:
                    label = f" {entry.label}" if entry.label else ""
                    draw_ui_text(
                        self._small,
                        f"0x{entry.effect_id:02x}{label}",
                        info_x,
                        info_y,
                        scale=UI_TEXT_SCALE,
                        color=UI_TEXT_COLOR,
                    )
                    info_y += ui_line_height(self._small, scale=UI_TEXT_SCALE) + 4
            else:
                draw_ui_text(self._small, "no known mapping", info_x, info_y, scale=UI_TEXT_SCALE, color=UI_HINT_COLOR)
                info_y += ui_line_height(self._small, scale=UI_TEXT_SCALE) + 4
            info_y += 8

        draw_ui_text(self._small, "Effect table", info_x, info_y, scale=UI_TEXT_SCALE, color=UI_TEXT_COLOR)
        info_y += ui_line_height(self._small, scale=UI_TEXT_SCALE) + 6
        for entry in EFFECT_ENTRIES:
            grid_label = entry.grid
            line = f"0x{entry.effect_id:02x} grid{grid_label} frame 0x{entry.frame:02x}"
            if entry.label:
                line += f" {entry.label}"
            color = UI_TEXT_COLOR if entry.grid == grid else UI_HINT_COLOR
            draw_ui_text(self._small, line, info_x, info_y, scale=UI_TEXT_SCALE, color=color)
            info_y += ui_line_height(self._small, scale=UI_TEXT_SCALE) + 3


@register_view("particles", "Particle atlas preview")
def build_particle_view(ctx: ViewContext) -> View:
    return ParticleView(ctx)
