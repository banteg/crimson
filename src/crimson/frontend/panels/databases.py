from __future__ import annotations

from typing import TYPE_CHECKING

import pyray as rl

from grim.audio import play_sfx, update_audio
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font

from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, UiButtonTextureSet, button_draw, button_update, button_width
from ..assets import MenuAssets, _ensure_texture_cache, load_menu_assets
from ..menu import (
    MENU_PANEL_OFFSET_X,
    MENU_PANEL_OFFSET_Y,
    MENU_PANEL_WIDTH,
    MENU_SCALE_SMALL_THRESHOLD,
    MENU_SIGN_HEIGHT,
    MENU_SIGN_OFFSET_X,
    MENU_SIGN_OFFSET_Y,
    MENU_SIGN_POS_X_PAD,
    MENU_SIGN_POS_Y,
    MENU_SIGN_POS_Y_SMALL,
    MENU_SIGN_WIDTH,
    UI_SHADOW_OFFSET,
    MenuView,
    _draw_menu_cursor,
    ensure_menu_ground,
)
from ..transitions import _draw_screen_fade
from .base import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS

if TYPE_CHECKING:
    from ...game import GameState
    from grim.terrain_render import GroundRenderer


# Shared panel layout (state_14/15/16 in the oracle): tall left panel + short right panel.
LEFT_PANEL_POS_X = -119.0
LEFT_PANEL_POS_Y = 185.0
LEFT_PANEL_HEIGHT = 378.0

RIGHT_PANEL_POS_X = 609.0
RIGHT_PANEL_POS_Y = 200.0
RIGHT_PANEL_HEIGHT = 254.0


class _DatabaseBaseView:
    def __init__(self, state: GameState) -> None:
        self._state = state
        self._assets: MenuAssets | None = None
        self._ground: GroundRenderer | None = None
        self._small_font: SmallFontData | None = None
        self._button_textures: UiButtonTextureSet | None = None

        self._cursor_pulse_time = 0.0
        self._widescreen_y_shift = 0.0
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._action: str | None = None

        self._back_button = UiButtonState("Back", force_wide=False)

    def open(self) -> None:
        layout_w = float(self._state.config.screen_width)
        self._widescreen_y_shift = MenuView._menu_widescreen_y_shift(layout_w)
        self._assets = load_menu_assets(self._state)
        self._ground = None if self._state.pause_background is not None else ensure_menu_ground(self._state)
        self._small_font = None
        self._cursor_pulse_time = 0.0
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._action = None

        cache = _ensure_texture_cache(self._state)
        button_md = cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture
        button_sm = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture
        self._button_textures = UiButtonTextureSet(button_sm=button_sm, button_md=button_md)
        self._back_button = UiButtonState("Back", force_wide=False)

        if self._state.audio is not None:
            play_sfx(self._state.audio, "sfx_ui_panelclick", rng=self._state.rng)

    def close(self) -> None:
        if self._small_font is not None:
            rl.unload_texture(self._small_font.texture)
            self._small_font = None
        self._button_textures = None
        self._assets = None
        self._ground = None
        self._action = None

    def take_action(self) -> str | None:
        action = self._action
        self._action = None
        return action

    def _ensure_small_font(self) -> SmallFontData:
        if self._small_font is not None:
            return self._small_font
        missing_assets: list[str] = []
        self._small_font = load_small_font(self._state.assets_dir, missing_assets)
        return self._small_font

    def _panel_top_left(self, *, pos_x: float, pos_y: float, scale: float) -> tuple[float, float]:
        x0 = pos_x + MENU_PANEL_OFFSET_X * scale
        y0 = pos_y + self._widescreen_y_shift + MENU_PANEL_OFFSET_Y * scale
        return float(x0), float(y0)

    def _draw_sign(self) -> None:
        assets = self._assets
        if assets is None or assets.sign is None:
            return
        sign = assets.sign
        screen_w = float(self._state.config.screen_width)
        sign_scale, shift_x = MenuView._sign_layout_scale(int(screen_w))
        pos_x = screen_w + MENU_SIGN_POS_X_PAD
        pos_y = MENU_SIGN_POS_Y if screen_w > MENU_SCALE_SMALL_THRESHOLD else MENU_SIGN_POS_Y_SMALL
        sign_w = MENU_SIGN_WIDTH * sign_scale
        sign_h = MENU_SIGN_HEIGHT * sign_scale
        offset_x = MENU_SIGN_OFFSET_X * sign_scale + shift_x
        offset_y = MENU_SIGN_OFFSET_Y * sign_scale
        rotation_deg = 0.0
        fx_detail = bool(self._state.config.data.get("fx_detail_0", 0))
        if fx_detail:
            MenuView._draw_ui_quad_shadow(
                texture=sign,
                src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
                dst=rl.Rectangle(pos_x + UI_SHADOW_OFFSET, pos_y + UI_SHADOW_OFFSET, sign_w, sign_h),
                origin=rl.Vector2(-offset_x, -offset_y),
                rotation_deg=rotation_deg,
            )
        MenuView._draw_ui_quad(
            texture=sign,
            src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
            dst=rl.Rectangle(pos_x, pos_y, sign_w, sign_h),
            origin=rl.Vector2(-offset_x, -offset_y),
            rotation_deg=rotation_deg,
            tint=rl.WHITE,
        )

    def update(self, dt: float) -> None:
        if self._state.audio is not None:
            update_audio(self._state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        self._cursor_pulse_time += min(float(dt), 0.1) * 1.1

        dt_ms = int(min(float(dt), 0.1) * 1000.0)
        if dt_ms > 0:
            self._timeline_ms = min(self._timeline_max_ms, int(self._timeline_ms + dt_ms))

        enabled = self._timeline_ms >= self._timeline_max_ms

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) and enabled:
            if self._state.audio is not None:
                play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
            self._action = "back_to_previous"
            return

        textures = self._button_textures
        if textures is None or (textures.button_md is None and textures.button_sm is None):
            return
        if not enabled:
            return

        scale = 0.9 if float(self._state.config.screen_width) < 641.0 else 1.0
        left_x0, left_y0 = self._panel_top_left(pos_x=LEFT_PANEL_POS_X, pos_y=LEFT_PANEL_POS_Y, scale=scale)

        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT)

        bx, by = self._back_button_pos()
        back_w = button_width(None, self._back_button.label, scale=scale, force_wide=self._back_button.force_wide)
        if button_update(
            self._back_button,
            x=left_x0 + float(bx) * scale,
            y=left_y0 + float(by) * scale,
            width=back_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            if self._state.audio is not None:
                play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
            self._action = "back_to_previous"

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        pause_background = self._state.pause_background
        if pause_background is not None:
            pause_background.draw_pause_background()
        elif self._ground is not None:
            self._ground.draw(0.0, 0.0)
        _draw_screen_fade(self._state)

        assets = self._assets
        if assets is None or assets.panel is None:
            return

        scale = 0.9 if float(self._state.config.screen_width) < 641.0 else 1.0
        fx_detail = bool(self._state.config.data.get("fx_detail_0", 0))

        panel_w = MENU_PANEL_WIDTH * scale
        _angle_rad, left_slide_x = MenuView._ui_element_anim(
            self,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
            direction_flag=0,
        )
        _angle_rad, right_slide_x = MenuView._ui_element_anim(
            self,
            index=2,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
            direction_flag=1,
        )

        left_x0, left_y0 = self._panel_top_left(pos_x=LEFT_PANEL_POS_X, pos_y=LEFT_PANEL_POS_Y, scale=scale)
        right_x0, right_y0 = self._panel_top_left(pos_x=RIGHT_PANEL_POS_X, pos_y=RIGHT_PANEL_POS_Y, scale=scale)
        left_x0 += float(left_slide_x)
        right_x0 += float(right_slide_x)

        draw_classic_menu_panel(
            assets.panel,
            dst=rl.Rectangle(left_x0, left_y0, panel_w, LEFT_PANEL_HEIGHT * scale),
            tint=rl.WHITE,
            shadow=fx_detail,
        )
        draw_classic_menu_panel(
            assets.panel,
            dst=rl.Rectangle(right_x0, right_y0, panel_w, RIGHT_PANEL_HEIGHT * scale),
            tint=rl.WHITE,
            shadow=fx_detail,
        )

        font = self._ensure_small_font()
        self._draw_contents(left_x0, left_y0, right_x0, right_y0, scale=scale, font=font)

        textures = self._button_textures
        if textures is not None and (textures.button_md is not None or textures.button_sm is not None):
            bx, by = self._back_button_pos()
            back_w = button_width(None, self._back_button.label, scale=scale, force_wide=self._back_button.force_wide)
            button_draw(
                textures,
                font,
                self._back_button,
                x=left_x0 + float(bx) * scale,
                y=left_y0 + float(by) * scale,
                width=back_w,
                scale=scale,
            )

        self._draw_sign()
        _draw_menu_cursor(self._state, pulse_time=self._cursor_pulse_time)

    def _back_button_pos(self) -> tuple[float, float]:
        raise NotImplementedError

    def _draw_contents(
        self,
        left_x0: float,
        left_y0: float,
        right_x0: float,
        right_y0: float,
        *,
        scale: float,
        font: SmallFontData,
    ) -> None:
        raise NotImplementedError


class UnlockedWeaponsDatabaseView(_DatabaseBaseView):
    def _back_button_pos(self) -> tuple[float, float]:
        # state_15: ui_buttonSm bbox [270,507]..[352,539] => relative to left panel (-98,194): (368, 313)
        return (368.0, 313.0)

    def _draw_contents(self, left_x0: float, left_y0: float, right_x0: float, right_y0: float, *, scale: float, font: SmallFontData) -> None:
        # state_15 title at (153,244) => relative to left panel (-98,194): (251,50)
        draw_small_text(
            font,
            "Unlocked Weapons Database",
            left_x0 + 251.0 * scale,
            left_y0 + 50.0 * scale,
            1.0 * scale,
            rl.Color(255, 255, 255, 255),
        )


class UnlockedPerksDatabaseView(_DatabaseBaseView):
    def _back_button_pos(self) -> tuple[float, float]:
        # state_16: ui_buttonSm bbox [258,509]..[340,541] => relative to left panel (-98,194): (356, 315)
        return (356.0, 315.0)

    def _draw_contents(self, left_x0: float, left_y0: float, right_x0: float, right_y0: float, *, scale: float, font: SmallFontData) -> None:
        # state_16 title at (163,244) => relative to left panel (-98,194): (261,50)
        draw_small_text(
            font,
            "Unlocked Perks Database",
            left_x0 + 261.0 * scale,
            left_y0 + 50.0 * scale,
            1.0 * scale,
            rl.Color(255, 255, 255, 255),
        )
