from __future__ import annotations

from pathlib import Path

import pyray as rl

from grim.assets import PaqTextureCache
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font
from grim.geom import Vec2
from grim.math import clamp

from ..demo_trial import DemoTrialOverlayInfo
from .perk_menu import (
    PerkMenuAssets,
    UiButtonState,
    button_draw,
    button_update,
    button_width,
    cursor_draw,
    wrap_ui_text,
)

DEMO_PURCHASE_URL = "http://buy.crimsonland.com"


class DemoTrialOverlayUi:
    def __init__(self, assets_root: Path) -> None:
        self._assets_root = assets_root
        self._cache: PaqTextureCache | None = None

        self._missing_assets: list[str] = []
        self._font: SmallFontData | None = None
        self._assets: PerkMenuAssets | None = None
        self._cl_logo: rl.Texture2D | None = None

        self._purchase_button = UiButtonState("Purchase", force_wide=True)
        self._maybe_later_button = UiButtonState("Maybe later", force_wide=True)

    def bind_cache(self, cache: PaqTextureCache | None) -> None:
        self._cache = cache

    def close(self) -> None:
        if self._font is not None:
            rl.unload_texture(self._font.texture)
            self._font = None
        self._assets = None
        self._cl_logo = None

    def _ensure_loaded(self) -> None:
        if self._font is None:
            self._missing_assets.clear()
            try:
                self._font = load_small_font(self._assets_root, self._missing_assets)
            except Exception:
                self._font = None

        cache = self._cache
        if cache is None:
            return

        if self._assets is None:
            cursor = cache.get_or_load("ui_cursor", "ui/ui_cursor.jaz").texture
            button_sm = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture
            button_md = cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture
            self._assets = PerkMenuAssets(
                menu_panel=None,
                title_pick_perk=None,
                title_level_up=None,
                menu_item=None,
                button_sm=button_sm,
                button_md=button_md,
                cursor=cursor,
                aim=None,
                missing=[],
            )

        if self._cl_logo is None:
            self._cl_logo = cache.get_or_load("cl_logo", "load/logo_crimsonland.tga").texture

    @staticmethod
    def _panel_xy(*, screen_w: float, screen_h: float) -> Vec2:
        return Vec2(screen_w * 0.5 - 256.0, screen_h * 0.5 - 128.0)

    def update(self, dt_ms: int) -> str | None:
        self._ensure_loaded()

        dt_ms = max(0, int(dt_ms))
        mouse = rl.get_mouse_position()
        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        mouse.x = clamp(float(mouse.x), 0.0, max(0.0, screen_w - 1.0))
        mouse.y = clamp(float(mouse.y), 0.0, max(0.0, screen_h - 1.0))

        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        panel_pos = self._panel_xy(screen_w=screen_w, screen_h=screen_h)

        font = self._font
        scale = 1.0
        button_w = button_width(font, self._purchase_button.label, scale=scale, force_wide=True)
        gap = 20.0
        row_w = button_w * 2.0 + gap
        button_base_pos = panel_pos + Vec2(256.0 - row_w * 0.5, 214.0)

        purchase_clicked = button_update(
            self._purchase_button,
            pos=button_base_pos,
            width=float(button_w),
            dt_ms=float(dt_ms),
            mouse=mouse,
            click=bool(click),
        )
        maybe_clicked = button_update(
            self._maybe_later_button,
            pos=button_base_pos + Vec2(button_w + gap, 0.0),
            width=float(button_w),
            dt_ms=float(dt_ms),
            mouse=mouse,
            click=bool(click),
        )

        if purchase_clicked:
            return "purchase"
        if maybe_clicked:
            return "maybe_later"
        return None

    def _draw_text_block(self, text: str, *, pos: Vec2, width: float, scale: float) -> float:
        font = self._font
        lines = wrap_ui_text(font, text, max_width=float(width), scale=float(scale))
        line_h = (font.cell_size if font is not None else 16) * scale
        color = rl.Color(220, 220, 220, 255)
        y_pos = float(pos.y)
        for line in lines:
            if font is not None:
                draw_small_text(font, line, Vec2(float(pos.x), y_pos), float(scale), color)
            else:
                rl.draw_text(line, int(pos.x), int(y_pos), int(20 * scale), color)
            y_pos += float(line_h)
        return y_pos

    def draw(self, info: DemoTrialOverlayInfo) -> None:
        if not info.visible:
            return
        self._ensure_loaded()

        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        panel_pos = self._panel_xy(screen_w=screen_w, screen_h=screen_h)

        rl.draw_rectangle(0, 0, int(screen_w), int(screen_h), rl.Color(0, 0, 0, 180))
        rl.draw_rectangle(int(panel_pos.x), int(panel_pos.y), 512, 256, rl.Color(18, 18, 22, 230))
        rl.draw_rectangle_lines(int(panel_pos.x), int(panel_pos.y), 512, 256, rl.Color(255, 255, 255, 255))

        logo = self._cl_logo
        if logo is not None:
            src = rl.Rectangle(0.0, 0.0, float(logo.width), float(logo.height))
            dst = rl.Rectangle(panel_pos.x + 72.0, panel_pos.y + 22.0, 371.2, 46.4)
            rl.draw_texture_pro(logo, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        font = self._font
        header = "You have been playing the Demo version of Crimsonland."
        if font is not None:
            draw_small_text(
                font, header, Vec2(panel_pos.x + 28.0, panel_pos.y + 9.0), 1.0, rl.Color(220, 220, 220, 255)
            )
        else:
            rl.draw_text(header, int(panel_pos.x + 28.0), int(panel_pos.y + 9.0), 16, rl.Color(220, 220, 220, 255))

        body = ""
        if info.kind == "quest_tier_limit":
            body = (
                "You have completed all Quest mode levels.\n"
                f"However, you still have {info.remaining_label} time left.\n\n"
                "If you would like to have unlimited play time and access to all features,\n"
                "please upgrade to the full version.\n\n"
                "Buy the full version to gain unrestricted game modes and be able to post your high scores online.\n"
                "Buy it now. You'll have a great time."
            )
        elif info.kind == "quest_grace_left":
            body = (
                "You have used up your play time in the Demo version.\n"
                f"You have {info.remaining_label} time left to play Quest mode.\n\n"
                "If you would like to have unlimited play time and access to all features,\n"
                "please upgrade to the full version.\n\n"
                "Buy the full version to gain unrestricted game modes and be able to post your high scores online.\n"
                "Buy it now. You'll have a great time."
            )
        else:
            body = (
                "Trial time is up.\n\n"
                "If you would like all features, please upgrade to the full version.\n"
                "Purchasing is very easy and takes just minutes.\n\n"
                "Buy the full version to gain unrestricted game modes and be able to post your high scores online.\n"
                "Buy it now. You'll have a great time."
            )

        text_x = panel_pos.x + 26.0
        text_y = panel_pos.y + 78.0
        text_w = 512.0 - 52.0
        self._draw_text_block(body, pos=Vec2(text_x, text_y), width=text_w, scale=1.0)

        assets = self._assets
        if assets is not None:
            scale = 1.0
            button_w = 145.0 * scale
            gap = 20.0
            row_w = button_w * 2.0 + gap
            button_base_pos = panel_pos + Vec2(256.0 - row_w * 0.5, 214.0)
            button_draw(
                assets,
                font,
                self._purchase_button,
                pos=button_base_pos,
                width=float(button_w),
                scale=float(scale),
            )
            button_draw(
                assets,
                font,
                self._maybe_later_button,
                pos=button_base_pos + Vec2(button_w + gap, 0.0),
                width=float(button_w),
                scale=float(scale),
            )
            cursor_draw(assets, mouse=rl.get_mouse_position(), scale=1.0, alpha=1.0)
