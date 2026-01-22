from __future__ import annotations

import pyray as rl

from ..grim2d.font import DEFAULT_SAMPLE
from .font_grim_mono import (
    GrimMonoFont,
    draw_grim_mono_text,
    load_grim_mono_font,
    measure_grim_mono_text_height,
)
from .font_small import (
    SmallFontData,
    draw_small_text,
    load_small_font,
    measure_small_text_height,
)
from .registry import register_view
from .types import View, ViewContext

SMALL_SAMPLE_SCALE = 1.0
UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)
QUEST_TITLE_ALPHA = 1.0
QUEST_NUMBER_ALPHA_RATIO = 0.5
QUEST_NUMBER_SCALE_DELTA = 0.2
# Game X formula: strlen * number_scale * 8.0 + number_scale * 32.0 + 4.0
# where 8.0 = advance/2, 32.0 = base gap, 4.0 = fixed offset
QUEST_NUMBER_HALF_ADVANCE = 8.0  # half of GRIM_MONO_ADVANCE (16/2)
QUEST_NUMBER_BASE_GAP = 32.0
QUEST_NUMBER_FIXED_OFFSET = 4.0
# Game Y formula: number_y = title_y + number_scale * (23.36 - 16.0)
# where 23.36 is constant at 0x46f5a0, 16.0 is font advance at 0x46f230
QUEST_NUMBER_Y_MULTIPLIER = 7.36  # 23.36 - 16.0

GRIM_MONO_FILTER_NAME = "Bilinear"
GRIM_MONO_FILTER_VALUE = rl.TEXTURE_FILTER_BILINEAR


class FontView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None
        self._grim_mono: GrimMonoFont | None = None
        self._sample = DEFAULT_SAMPLE

    def _ui_line_height(self, scale: float = UI_TEXT_SCALE) -> int:
        if self._small is not None:
            return int(self._small.cell_size * scale)
        return int(20 * scale)

    def _draw_ui_text(
        self, text: str, x: float, y: float, color: rl.Color, scale: float = UI_TEXT_SCALE
    ) -> None:
        if self._small is not None:
            draw_small_text(self._small, text, x, y, scale, color)
        else:
            rl.draw_text(text, int(x), int(y), int(20 * scale), color)

    def close(self) -> None:
        if self._small is not None:
            rl.unload_texture(self._small.texture)
        if self._grim_mono is not None:
            rl.unload_texture(self._grim_mono.texture)

    def open(self) -> None:
        self._missing_assets.clear()
        self._small = load_small_font(self._assets_root, self._missing_assets)
        self._grim_mono = load_grim_mono_font(self._assets_root, self._missing_assets)
        self._apply_grim_filter()

    def update(self, dt: float) -> None:
        del dt

    def _apply_grim_filter(self) -> None:
        if self._grim_mono is None:
            return
        rl.set_texture_filter(self._grim_mono.texture, GRIM_MONO_FILTER_VALUE)

    def draw(self) -> None:
        rl.clear_background(rl.Color(12, 12, 14, 255))
        if self._missing_assets:
            message = "Missing assets: " + ", ".join(self._missing_assets)
            self._draw_ui_text(message, 24, 24, UI_ERROR_COLOR)
            return
        y = 24
        self._draw_ui_text("Small font", 24, y, UI_TEXT_COLOR)
        y += self._ui_line_height() + 12
        if self._small is not None:
            draw_small_text(
                self._small, self._sample, 24, y, SMALL_SAMPLE_SCALE, rl.WHITE
            )
            y += (
                int(
                    measure_small_text_height(
                        self._small, self._sample, SMALL_SAMPLE_SCALE
                    )
                )
                + 40
            )

        self._draw_ui_text("Grim2D mono font", 24, y, UI_TEXT_COLOR)
        y += self._ui_line_height() + 12
        if self._grim_mono is not None:
            self._draw_ui_text(f"Filter: {GRIM_MONO_FILTER_NAME}", 24, y, UI_TEXT_COLOR)
            y += self._ui_line_height(0.9) + 6
            mono_scale = self._quest_title_scale()
            draw_grim_mono_text(
                self._grim_mono, self._sample, 24, y, mono_scale, rl.WHITE
            )
            y += (
                int(
                    measure_grim_mono_text_height(
                        self._grim_mono, self._sample, mono_scale
                    )
                )
                + 20
            )

        self._draw_quest_title_overlay()

    def _quest_title_scale(self) -> float:
        return 0.75 if rl.get_screen_width() <= 640 else 0.8

    def _draw_quest_title_overlay(self) -> None:
        if self._grim_mono is None:
            return
        font = self._grim_mono
        title = "Land Hostile"
        number = "1.10"
        title_scale = self._quest_title_scale()
        number_scale = max(0.0, title_scale - QUEST_NUMBER_SCALE_DELTA)

        title_width = len(title) * font.advance * title_scale

        center_x = rl.get_screen_width() / 2.0
        title_x = center_x - (title_width / 2.0)
        # Game formula: x = title_x - (strlen * scale * 8) - (scale * 32) - 4
        number_x = (
            title_x
            - (len(number) * number_scale * QUEST_NUMBER_HALF_ADVANCE)
            - (number_scale * QUEST_NUMBER_BASE_GAP)
            - QUEST_NUMBER_FIXED_OFFSET
        )

        title_y = (rl.get_screen_height() / 2.0) - 32.0
        # Game formula: y = title_y + number_scale * (23.36 - 16.0)
        number_y = title_y + (number_scale * QUEST_NUMBER_Y_MULTIPLIER)

        title_color = rl.Color(255, 255, 255, int(255 * QUEST_TITLE_ALPHA))
        number_color = rl.Color(
            255, 255, 255, int(255 * QUEST_TITLE_ALPHA * QUEST_NUMBER_ALPHA_RATIO)
        )

        draw_grim_mono_text(font, title, title_x, title_y, title_scale, title_color)
        draw_grim_mono_text(font, number, number_x, number_y, number_scale, number_color)


@register_view("fonts", "Font preview")
def build_font_view(ctx: ViewContext) -> View:
    return FontView(ctx)
