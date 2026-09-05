from __future__ import annotations

from pathlib import Path

from grim.assets import TextureId, runtime_resources_for
from grim.fonts.small import draw_small_text, load_small_font
from grim.geom import Vec2
from grim.math import clamp
from grim.raylib_api import rl

from ..demo_trial import DemoTrialOverlayInfo
from .cursor import draw_menu_cursor
from .perk_menu import UiButtonState, button_draw, button_update, button_width

DEMO_PURCHASE_URL = "http://buy.crimsonland.com"
_DEMO_HEADER_TEXT = "You've been playing the Demo version of"
_QUEST_COMPLETED_TEXT = "You've completed all Quest mode levels available in the Demo version."
_QUEST_LIMIT_REMAINING_TEXT = "However, you still have {remaining} time left to play Survival and Rush game modes."
_QUEST_GRACE_USED_UP_TEXT = "You have used up your play time in this game mode. However, you still"
_QUEST_GRACE_REMAINING_TEXT = "have {remaining} time left to play Quest mode levels only."
_UPGRADE_ALL_FEATURES_TEXT = "If you would like to have unlimited play time and access to all features,"
_UPGRADE_FEATURES_LINE_TEXT = "The full version features unrestricted access to all 3"
_UPGRADE_BUY_FULL_TEXT = "Buy the full version to gain unrestricted access to all 3"
_UPGRADE_BUY_LINE_TEXT = "game modes and be able to post your scores on the Internet. Why not buy"
_UPGRADE_TRAILER_TEXT = "it now? You'll have a great time!"
_UPGRADE_PLEASE_TEXT = "please upgrade to the full version of Crimsonland."
_UPGRADE_PROCESS_TEXT = "please upgrade to the full version of Crimsonland.  The process is very easy"
_UPGRADE_PROCESS_CONT_TEXT = "and takes just minutes. "
_UPGRADE_EASY_TEXT = "is very easy and takes just minutes."
_TIME_UP_TEXT = "Trial time is up. If you would like to have unlimited play time and access to"
_TIME_UP_ALL_FEATURES_TEXT = "all features, please upgrade to the full version of Crimsonland.  The process"


def _overlay_body_lines(info: DemoTrialOverlayInfo) -> tuple[tuple[float, str], ...]:
    if info.kind == "quest_tier_limit":
        if info.show_remaining_line:
            return (
                (74.0, _QUEST_COMPLETED_TEXT),
                (92.0, _QUEST_LIMIT_REMAINING_TEXT.format(remaining=info.remaining_label)),
                (124.0, _UPGRADE_ALL_FEATURES_TEXT),
                (142.0, _UPGRADE_PLEASE_TEXT),
                (164.0, _UPGRADE_FEATURES_LINE_TEXT),
                (182.0, _UPGRADE_BUY_LINE_TEXT),
                (200.0, _UPGRADE_TRAILER_TEXT),
            )
        return (
            (86.0, _QUEST_COMPLETED_TEXT),
            (104.0, _UPGRADE_ALL_FEATURES_TEXT),
            (122.0, _UPGRADE_PLEASE_TEXT),
            (144.0, _UPGRADE_FEATURES_LINE_TEXT),
            (162.0, _UPGRADE_BUY_LINE_TEXT),
            (180.0, _UPGRADE_TRAILER_TEXT),
        )
    if info.kind == "quest_grace_left":
        return (
            (73.0, _QUEST_GRACE_USED_UP_TEXT),
            (89.0, _QUEST_GRACE_REMAINING_TEXT.format(remaining=info.remaining_label)),
            (111.0, _UPGRADE_ALL_FEATURES_TEXT),
            (127.0, _UPGRADE_PROCESS_TEXT),
            (143.0, _UPGRADE_PROCESS_CONT_TEXT),
            (165.0, _UPGRADE_BUY_FULL_TEXT),
            (181.0, _UPGRADE_BUY_LINE_TEXT),
            (197.0, _UPGRADE_TRAILER_TEXT),
        )
    return (
        (80.0, _TIME_UP_TEXT),
        (98.0, _TIME_UP_ALL_FEATURES_TEXT),
        (116.0, _UPGRADE_EASY_TEXT),
        (140.0, _UPGRADE_BUY_FULL_TEXT),
        (158.0, _UPGRADE_BUY_LINE_TEXT),
        (176.0, _UPGRADE_TRAILER_TEXT),
    )


class DemoTrialOverlayUi:
    def __init__(self, assets_root: Path) -> None:
        self._assets_root = assets_root

        self._font = load_small_font(self._assets_root)
        self._resources = runtime_resources_for(self._assets_root)
        self._cursor_pulse_time = 0.0

        self._purchase_button = UiButtonState("Purchase", force_wide=True)
        self._maybe_later_button = UiButtonState("Maybe later", force_wide=True)

    def close(self) -> None:
        self._cursor_pulse_time = 0.0

    @staticmethod
    def _panel_xy(*, screen_w: float, screen_h: float) -> Vec2:
        return Vec2(screen_w * 0.5 - 256.0, screen_h * 0.5 - 128.0)

    def update(self, dt_ms: int) -> str | None:
        dt_ms = max(0, int(dt_ms))
        self._cursor_pulse_time += float(dt_ms) * 0.001 * 1.1
        mouse = rl.get_mouse_position()
        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        mouse.x = clamp(mouse.x, 0.0, max(0.0, screen_w - 1.0))
        mouse.y = clamp(mouse.y, 0.0, max(0.0, screen_h - 1.0))

        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        panel_pos = self._panel_xy(screen_w=screen_w, screen_h=screen_h)

        scale = 1.0
        button_w = button_width(self._resources, self._purchase_button.label, scale=scale, force_wide=True)
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
            pos=button_base_pos.offset(dx=button_w + gap),
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

    def draw(self, info: DemoTrialOverlayInfo) -> None:
        if not info.visible:
            return

        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        panel_pos = self._panel_xy(screen_w=screen_w, screen_h=screen_h)

        rl.draw_rectangle(int(panel_pos.x), int(panel_pos.y), 512, 256, rl.Color(18, 18, 22, 230))
        rl.draw_rectangle_lines(int(panel_pos.x), int(panel_pos.y), 512, 256, rl.Color(255, 255, 255, 255))

        logo = self._resources.texture(TextureId.CL_LOGO)
        src = rl.Rectangle(0.0, 0.0, float(logo.width), float(logo.height))
        dst = rl.Rectangle(panel_pos.x + 72.0, panel_pos.y + 22.0, 371.2, 46.4)
        rl.draw_texture_pro(logo, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        font = self._font
        if font is not None:
            draw_small_text(
                font, _DEMO_HEADER_TEXT, Vec2(panel_pos.x + 131.0, panel_pos.y + 9.0), rl.Color(220, 220, 220, 255),
            )
        else:
            rl.draw_text(
                _DEMO_HEADER_TEXT, int(panel_pos.x + 131.0), int(panel_pos.y + 9.0), 16, rl.Color(220, 220, 220, 255),
            )

        body_x = panel_pos.x + 26.0
        body_color = rl.Color(220, 220, 220, 255)
        for y_offset, line in _overlay_body_lines(info):
            if font is not None:
                draw_small_text(font, line, Vec2(body_x, panel_pos.y + y_offset), body_color)
            else:
                rl.draw_text(line, int(body_x), int(panel_pos.y + y_offset), 16, body_color)

        scale = 1.0
        button_w = 145.0 * scale
        gap = 20.0
        row_w = button_w * 2.0 + gap
        button_base_pos = panel_pos + Vec2(256.0 - row_w * 0.5, 214.0)
        button_draw(
            self._resources,
            self._purchase_button,
            pos=button_base_pos,
            width=float(button_w),
            scale=float(scale),
        )
        button_draw(
            self._resources,
            self._maybe_later_button,
            pos=button_base_pos.offset(dx=button_w + gap),
            width=float(button_w),
            scale=float(scale),
        )
        draw_menu_cursor(
            self._resources.texture(TextureId.PARTICLES),
            self._resources.texture(TextureId.UI_CURSOR),
            pos=Vec2.from_xy(rl.get_mouse_position()),
            pulse_time=float(self._cursor_pulse_time),
        )
