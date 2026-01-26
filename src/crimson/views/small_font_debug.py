from __future__ import annotations

import pyray as rl

from grim.fonts.small import SmallFontData, load_small_font
from grim.view import View, ViewContext

from ..ui.perk_menu import draw_menu_item
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


class SmallFontDebugView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None
        self._screenshot_requested = False

    def open(self) -> None:
        self._missing_assets.clear()
        self._small = load_small_font(self._assets_root, self._missing_assets)

    def close(self) -> None:
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None

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

        rl.draw_text("smallWhite atlas", margin, header_y, 20, UI_TEXT_COLOR)
        atlas_y = header_y + 28
        rl.draw_texture(self._small.texture, margin, atlas_y, rl.WHITE)

        right_x = margin + self._small.texture.width + gap
        rl.draw_text("perk menu render", right_x, header_y, 20, UI_TEXT_COLOR)
        text_y = float(atlas_y)
        for line in SAMPLE_LINES:
            draw_menu_item(self._small, line, x=float(right_x), y=text_y, scale=1.0, hovered=False)
            text_y += row_step


@register_view("small-font-debug", "Small font debug")
def build_small_font_debug_view(ctx: ViewContext) -> View:
    return SmallFontDebugView(ctx)
