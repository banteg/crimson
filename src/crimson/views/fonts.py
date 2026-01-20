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
QUEST_NUMBER_Y_OFFSET_BASE = 4.048
QUEST_NUMBER_Y_OFFSET_REF_SCALE = 0.75
QUEST_NUMBER_X_OFFSET_BASE = 46.72

GRIM_MONO_FILTERS = [
    ("Point", rl.TEXTURE_FILTER_POINT),
    ("Bilinear", rl.TEXTURE_FILTER_BILINEAR),
    ("Trilinear", rl.TEXTURE_FILTER_TRILINEAR),
]
GRIM_MONO_DEFAULT_FILTER_INDEX = 2
GRIM_MONO_FILTER_KEY = rl.KeyboardKey.KEY_F


class FontView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None
        self._grim_mono: GrimMonoFont | None = None
        self._sample = DEFAULT_SAMPLE
        self._grim_filter_index = GRIM_MONO_DEFAULT_FILTER_INDEX
        self._grim_has_mipmaps = False

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
        self._grim_filter_index = GRIM_MONO_DEFAULT_FILTER_INDEX
        self._grim_has_mipmaps = False
        self._apply_grim_filter()

    def update(self, dt: float) -> None:
        del dt
        self._handle_input()

    def _handle_input(self) -> None:
        if rl.is_key_pressed(GRIM_MONO_FILTER_KEY):
            self._cycle_grim_filter(1)

    def _cycle_grim_filter(self, delta: int) -> None:
        if not GRIM_MONO_FILTERS:
            return
        self._grim_filter_index = (self._grim_filter_index + delta) % len(
            GRIM_MONO_FILTERS
        )
        self._apply_grim_filter()

    def _apply_grim_filter(self) -> None:
        if self._grim_mono is None:
            return
        name, value = GRIM_MONO_FILTERS[self._grim_filter_index]
        if value == rl.TEXTURE_FILTER_TRILINEAR and not self._grim_has_mipmaps:
            gen = getattr(rl, "gen_texture_mipmaps", None)
            if gen is not None:
                gen(self._grim_mono.texture)
                self._grim_has_mipmaps = True
        rl.set_texture_filter(self._grim_mono.texture, value)

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
            filter_name, _ = GRIM_MONO_FILTERS[self._grim_filter_index]
            self._draw_ui_text(
                f"Filter: {filter_name} (F to cycle)", 24, y, UI_TEXT_COLOR
            )
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
        number = "1.1"
        title_scale = self._quest_title_scale()
        number_scale = max(0.0, title_scale - QUEST_NUMBER_SCALE_DELTA)

        title_width = len(title) * font.advance * title_scale
        number_width = len(number) * font.advance * number_scale

        center_x = rl.get_screen_width() / 2.0
        title_x = center_x - (title_width / 2.0)
        number_x = title_x - (QUEST_NUMBER_X_OFFSET_BASE * title_scale)

        title_y = (rl.get_screen_height() / 2.0) - 32.0
        number_y = title_y + (QUEST_NUMBER_Y_OFFSET_BASE * (title_scale / QUEST_NUMBER_Y_OFFSET_REF_SCALE))

        title_color = rl.Color(255, 255, 255, int(255 * QUEST_TITLE_ALPHA))
        number_color = rl.Color(
            255, 255, 255, int(255 * QUEST_TITLE_ALPHA * QUEST_NUMBER_ALPHA_RATIO)
        )

        draw_grim_mono_text(font, title, title_x, title_y, title_scale, title_color)
        draw_grim_mono_text(font, number, number_x, number_y, number_scale, number_color)


@register_view("fonts", "Font preview")
def build_font_view(ctx: ViewContext) -> View:
    return FontView(ctx)
