from __future__ import annotations
from grim.geom import Vec2

import pyray as rl
from ._ui_helpers import draw_ui_text, ui_line_height
from .quest_title_overlay import (
    draw_quest_title_overlay,
    quest_title_base_scale,
)
from .registry import register_view
from grim.fonts.grim_mono import (
    GrimMonoFont,
    draw_grim_mono_text,
    load_grim_mono_font,
    measure_grim_mono_text_height,
)
from grim.fonts.small import (
    SmallFontData,
    draw_small_text,
    load_small_font,
    measure_small_text_height,
)
from grim.view import View, ViewContext

DEFAULT_SAMPLE = """CRIMSONLAND
The quick brown fox jumps over the lazy dog.
0123456789 !@#$%^&*()[]{}<>?/\\"""

SMALL_SAMPLE_SCALE = 1.0
UI_TEXT_SCALE = 1.0
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)

GRIM_MONO_FILTER_NAME = "Bilinear"
GRIM_MONO_FILTER_VALUE = rl.TEXTURE_FILTER_BILINEAR


class FontView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None
        self._grim_mono: GrimMonoFont | None = None
        self._sample = DEFAULT_SAMPLE

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
            draw_ui_text(self._small, message, Vec2(24, 24), scale=UI_TEXT_SCALE, color=UI_ERROR_COLOR)
            return
        y = 24
        draw_ui_text(self._small, "Small font", Vec2(24, y), scale=UI_TEXT_SCALE, color=UI_TEXT_COLOR)
        y += ui_line_height(self._small, scale=UI_TEXT_SCALE) + 12
        if self._small is not None:
            draw_small_text(self._small, self._sample, Vec2(24, y), SMALL_SAMPLE_SCALE, rl.WHITE)
            y += int(measure_small_text_height(self._small, self._sample, SMALL_SAMPLE_SCALE)) + 40

        draw_ui_text(self._small, "Grim2D mono font", Vec2(24, y), scale=UI_TEXT_SCALE, color=UI_TEXT_COLOR)
        y += ui_line_height(self._small, scale=UI_TEXT_SCALE) + 12
        if self._grim_mono is not None:
            draw_ui_text(
                self._small, f"Filter: {GRIM_MONO_FILTER_NAME}", Vec2(24, y), scale=UI_TEXT_SCALE, color=UI_TEXT_COLOR
            )
            y += ui_line_height(self._small, scale=0.9) + 6
            mono_scale = quest_title_base_scale(rl.get_screen_width())
            draw_grim_mono_text(self._grim_mono, self._sample, Vec2(24, y), mono_scale, rl.WHITE)
            y += int(measure_grim_mono_text_height(self._grim_mono, self._sample, mono_scale)) + 20

        self._draw_quest_title_overlay()

    def _draw_quest_title_overlay(self) -> None:
        if self._grim_mono is None:
            return
        draw_quest_title_overlay(self._grim_mono, "Land Hostile", "1.10")


@register_view("fonts", "Font preview")
def build_font_view(ctx: ViewContext) -> View:
    return FontView(ctx)
