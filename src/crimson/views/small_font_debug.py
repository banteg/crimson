from __future__ import annotations

from pathlib import Path

import pyray as rl

from grim.fonts.small import SmallFontData, load_small_font
from grim.geom import Vec2
from grim.view import View, ViewContext

from ..ui.perk_menu import MENU_ITEM_ALPHA_IDLE, MENU_ITEM_RGB, draw_menu_item
from .registry import register_view

UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)

SAMPLE_LINES = [
    "Regeneration",
    "My Favourite Weapon",
    "Ammo Maniac",
    "Pyromaniac",
    "Evil Eyes",
]

ARIAL_FONT_LOAD_SIZE = 26
ARIAL_FONT_DRAW_SIZE = 13
PIXEL_ARIAL_LOAD_SIZE = 22
PIXEL_ARIAL_DRAW_SIZE = 11
VECTOR_FONT_SPACING = 1.0
VECTOR_FONT_FILTER = rl.TextureFilter.TEXTURE_FILTER_BILINEAR


class SmallFontDebugView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None
        self._screenshot_requested = False
        self._vector_font: rl.Font | None = None
        self._vector_font_path: Path | None = None
        self._vector_font_alt: rl.Font | None = None
        self._vector_font_alt_path: Path | None = None

    def open(self) -> None:
        self._missing_assets.clear()
        self._small = load_small_font(self._assets_root, self._missing_assets)
        self._vector_font = None
        self._vector_font_path = None
        self._vector_font_alt = None
        self._vector_font_alt_path = None
        for candidate in (
            self._assets_root / "crimson" / "load" / "arial.ttf",
            self._assets_root / "fonts" / "arial.ttf",
            self._assets_root / "arial.ttf",
        ):
            if not candidate.is_file():
                continue
            try:
                self._vector_font = rl.load_font_ex(str(candidate), ARIAL_FONT_LOAD_SIZE, None, 0)
                rl.set_texture_filter(self._vector_font.texture, VECTOR_FONT_FILTER)
                self._vector_font_path = candidate
                break
            except Exception:
                self._vector_font = None
                self._vector_font_path = None
        for candidate in (
            self._assets_root / "crimson" / "load" / "PIXEARG_.TTF",
            self._assets_root / "fonts" / "PIXEARG_.TTF",
            self._assets_root / "PIXEARG_.TTF",
        ):
            if not candidate.is_file():
                continue
            try:
                self._vector_font_alt = rl.load_font_ex(str(candidate), PIXEL_ARIAL_LOAD_SIZE, None, 0)
                rl.set_texture_filter(self._vector_font_alt.texture, VECTOR_FONT_FILTER)
                self._vector_font_alt_path = candidate
                break
            except Exception:
                self._vector_font_alt = None
                self._vector_font_alt_path = None

    def close(self) -> None:
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None
        if self._vector_font is not None:
            rl.unload_font(self._vector_font)
            self._vector_font = None
            self._vector_font_path = None
        if self._vector_font_alt is not None:
            rl.unload_font(self._vector_font_alt)
            self._vector_font_alt = None
            self._vector_font_alt_path = None

    def update(self, dt: float) -> None:
        del dt
        if rl.is_key_pressed(rl.KeyboardKey.KEY_P):
            self._screenshot_requested = True

    def consume_screenshot_request(self) -> bool:
        requested = self._screenshot_requested
        self._screenshot_requested = False
        return requested

    def draw(self) -> None:
        rl.clear_background(rl.Color(12, 12, 14, 255))
        if self._missing_assets:
            rl.draw_text(
                "Missing assets: " + ", ".join(self._missing_assets),
                24,
                24,
                20,
                UI_ERROR_COLOR,
            )
            return
        if self._small is None:
            return

        margin = 24
        gap = 40
        header_y = 20
        row_step = 19.0
        vector_step = row_step

        rl.draw_text("smallWhite atlas", margin, header_y, 20, UI_TEXT_COLOR)
        atlas_y = header_y + 28
        rl.draw_texture(self._small.texture, margin, atlas_y, rl.WHITE)

        right_x = margin + self._small.texture.width + gap
        rl.draw_text("perk menu render", right_x, header_y, 20, UI_TEXT_COLOR)
        text_y = float(atlas_y)
        for line in SAMPLE_LINES:
            draw_menu_item(self._small, line, pos=Vec2(float(right_x), text_y), scale=1.0, hovered=False)
            text_y += row_step
        perk_list_bottom = text_y
        section_y = perk_list_bottom + 16.0

        vector_x = right_x
        rl.draw_text("Pixel Arial (PIXEARG_.TTF)", vector_x, int(section_y), 20, UI_TEXT_COLOR)
        if self._vector_font_alt is None:
            hint_y = section_y + 28.0
            rl.draw_text("Place PIXEARG_.TTF in:", vector_x, int(hint_y), 16, UI_TEXT_COLOR)
            rl.draw_text(str(self._assets_root / "crimson" / "load"), vector_x, int(hint_y + 18), 16, UI_TEXT_COLOR)
            rl.draw_text(str(self._assets_root / "fonts"), vector_x, int(hint_y + 36), 16, UI_TEXT_COLOR)
            vector_list_end = hint_y + 54.0
        else:
            vector_y = section_y + 28.0
            for line in SAMPLE_LINES:
                self._draw_vector_menu_item(
                    self._vector_font_alt,
                    line,
                    pos=Vec2(float(vector_x), float(vector_y)),
                    font_size_px=PIXEL_ARIAL_DRAW_SIZE,
                    spacing=VECTOR_FONT_SPACING,
                )
                vector_y += vector_step
            vector_list_end = vector_y
        alt_x = vector_x
        alt_header_y = vector_list_end + 24.0
        rl.draw_text("Arial (ttf)", alt_x, int(alt_header_y), 20, UI_TEXT_COLOR)
        if self._vector_font is None:
            hint_y = alt_header_y + 28.0
            rl.draw_text("Place arial.ttf in:", alt_x, int(hint_y), 16, UI_TEXT_COLOR)
            rl.draw_text(str(self._assets_root / "crimson" / "load"), alt_x, int(hint_y + 18), 16, UI_TEXT_COLOR)
            rl.draw_text(str(self._assets_root / "fonts"), alt_x, int(hint_y + 36), 16, UI_TEXT_COLOR)
        else:
            alt_y = alt_header_y + 28.0
            for line in SAMPLE_LINES:
                self._draw_vector_menu_item(
                    self._vector_font,
                    line,
                    pos=Vec2(float(alt_x), float(alt_y)),
                    font_size_px=ARIAL_FONT_DRAW_SIZE,
                    spacing=VECTOR_FONT_SPACING,
                )
                alt_y += vector_step

    def _draw_vector_menu_item(
        self,
        font: rl.Font,
        text: str,
        *,
        pos: Vec2,
        font_size_px: float,
        spacing: float,
    ) -> None:
        r, g, b = MENU_ITEM_RGB
        color = rl.Color(int(r), int(g), int(b), int(255 * MENU_ITEM_ALPHA_IDLE))
        rl.draw_text_ex(font, text, pos.to_rl(), float(font_size_px), float(spacing), color)
        try:
            size = rl.measure_text_ex(font, text, float(font_size_px), float(spacing))
            width = size.x
        except Exception:
            width = float(rl.measure_text(text, int(font_size_px)))
        line_y = pos.y + 13.0
        rl.draw_line(int(pos.x), int(line_y), int(pos.x + width), int(line_y), color)


@register_view("small-font-debug", "Small font debug")
def build_small_font_debug_view(ctx: ViewContext) -> View:
    return SmallFontDebugView(ctx)
