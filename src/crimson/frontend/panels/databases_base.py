from __future__ import annotations

from grim.audio import play_sfx, update_audio
from grim.fonts.small import SmallFontData, load_small_font
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer

from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, UiButtonTextureSet, button_draw, button_update, button_width
from ..assets import MenuAssets, _ensure_texture_cache, load_menu_assets
from ..high_scores_layout import hs_left_panel_pos_x, hs_right_panel_pos_x
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
    menu_ground_camera,
)
from ..transitions import _draw_screen_fade
from ..types import FrontendContext
from .base import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS

# Shared panel layout (state_14/15/16 in the oracle): tall left panel + short right panel.
LEFT_PANEL_POS_Y = 185.0
LEFT_PANEL_HEIGHT = 378.0
RIGHT_PANEL_POS_Y = 200.0
RIGHT_PANEL_HEIGHT = 254.0


class _DatabaseBaseView:
    def __init__(self, state: FrontendContext) -> None:
        self.state = state
        self._is_open = False
        self._assets: MenuAssets | None = None
        self._ground: GroundRenderer | None = None
        self._small_font: SmallFontData | None = None
        self._button_textures: UiButtonTextureSet | None = None

        self._cursor_pulse_time = 0.0
        self._widescreen_y_shift = 0.0
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._closing = False
        self._close_action: str | None = None
        self._pending_action: str | None = None
        self._action: str | None = None

        self._back_button = UiButtonState("Back", force_wide=False)

    def open(self) -> None:
        layout_w = float(self.state.config.screen_width)
        self._widescreen_y_shift = MenuView._menu_widescreen_y_shift(layout_w)
        self._assets = load_menu_assets(self.state)
        self._ground = None if self.state.pause_background is not None else ensure_menu_ground(self.state)
        self._small_font = None
        self._cursor_pulse_time = 0.0
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._closing = False
        self._close_action = None
        self._pending_action = None
        self._action = None

        cache = _ensure_texture_cache(self.state)
        button_md = cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture
        button_sm = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture
        self._button_textures = UiButtonTextureSet(button_sm=button_sm, button_md=button_md)
        self._back_button = UiButtonState("Back", force_wide=False)

        if self.state.audio is not None:
            play_sfx(self.state.audio, "sfx_ui_panelclick", rng=self.state.rng)
        self._is_open = True

    def close(self) -> None:
        self._is_open = False
        if self._small_font is not None:
            rl.unload_texture(self._small_font.texture)
            self._small_font = None
        self._button_textures = None
        self._assets = None
        self._ground = None
        self._closing = False
        self._close_action = None
        self._pending_action = None
        self._action = None

    def take_action(self) -> str | None:
        self._assert_open()
        if self._pending_action is not None:
            action = self._pending_action
            self._pending_action = None
            self._closing = False
            self._close_action = None
            self._timeline_ms = self._timeline_max_ms
            return action
        action = self._action
        self._action = None
        return action

    def _assert_open(self) -> None:
        assert self._is_open, f"{self.__class__.__name__} must be opened before use"

    def _ensure_small_font(self) -> SmallFontData:
        if self._small_font is not None:
            return self._small_font
        self._small_font = load_small_font(self.state.assets_dir)
        return self._small_font

    def _panel_top_left(self, *, pos: Vec2, scale: float) -> Vec2:
        return Vec2(
            pos.x + MENU_PANEL_OFFSET_X * scale,
            pos.y + self._widescreen_y_shift + MENU_PANEL_OFFSET_Y * scale,
        )

    def _begin_close_transition(self, action: str) -> None:
        if self._closing:
            return
        self._closing = True
        self._close_action = action

    def _draw_sign(self) -> None:
        assets = self._assets
        assert assets is not None, "Database panel assets must be loaded before drawing sign"
        sign = assets.sign
        screen_w = float(self.state.config.screen_width)
        sign_scale, shift_x = MenuView._sign_layout_scale(int(screen_w))
        sign_pos = Vec2(
            screen_w + MENU_SIGN_POS_X_PAD,
            MENU_SIGN_POS_Y if screen_w > MENU_SCALE_SMALL_THRESHOLD else MENU_SIGN_POS_Y_SMALL,
        )
        sign_w = MENU_SIGN_WIDTH * sign_scale
        sign_h = MENU_SIGN_HEIGHT * sign_scale
        offset_x = MENU_SIGN_OFFSET_X * sign_scale + shift_x
        offset_y = MENU_SIGN_OFFSET_Y * sign_scale
        rotation_deg = 0.0
        fx_detail = self.state.config.fx_detail(level=0, default=False)
        if fx_detail:
            MenuView._draw_ui_quad_shadow(
                texture=sign,
                src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
                dst=rl.Rectangle(sign_pos.x + UI_SHADOW_OFFSET, sign_pos.y + UI_SHADOW_OFFSET, sign_w, sign_h),
                origin=rl.Vector2(-offset_x, -offset_y),
                rotation_deg=rotation_deg,
            )
        MenuView._draw_ui_quad(
            texture=sign,
            src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
            dst=rl.Rectangle(sign_pos.x, sign_pos.y, sign_w, sign_h),
            origin=rl.Vector2(-offset_x, -offset_y),
            rotation_deg=rotation_deg,
            tint=rl.WHITE,
        )

    def update(self, dt: float) -> None:
        self._assert_open()
        if self.state.audio is not None:
            update_audio(self.state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        self._cursor_pulse_time += min(float(dt), 0.1) * 1.1

        dt_ms = int(min(float(dt), 0.1) * 1000.0)
        if self._closing:
            if dt_ms > 0 and self._pending_action is None:
                self._timeline_ms -= dt_ms
                if self._timeline_ms < 0 and self._close_action is not None:
                    self._pending_action = self._close_action
                    self._close_action = None
            return

        if dt_ms > 0:
            self._timeline_ms = min(self._timeline_max_ms, int(self._timeline_ms + dt_ms))

        enabled = self._timeline_ms >= self._timeline_max_ms

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) and enabled:
            if self.state.audio is not None:
                play_sfx(self.state.audio, "sfx_ui_buttonclick", rng=self.state.rng)
            self._begin_close_transition("back_to_previous")
            return

        textures = self._button_textures
        if textures is None or (textures.button_md is None and textures.button_sm is None):
            return
        if not enabled:
            return

        screen_width = float(self.state.config.screen_width)
        scale = 1.0
        left_panel_pos_x = hs_left_panel_pos_x(screen_width)
        left_top_left = self._panel_top_left(pos=Vec2(left_panel_pos_x, LEFT_PANEL_POS_Y), scale=scale)
        font = self._ensure_small_font()

        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        self._update_content_interaction(left_top_left=left_top_left, scale=scale, mouse=mouse)

        back_pos = self._back_button_pos()
        back_w = button_width(font, self._back_button.label, scale=scale, force_wide=self._back_button.force_wide)
        if button_update(
            self._back_button,
            pos=left_top_left + back_pos * scale,
            width=back_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            if self.state.audio is not None:
                play_sfx(self.state.audio, "sfx_ui_buttonclick", rng=self.state.rng)
            self._begin_close_transition("back_to_previous")

    def draw(self) -> None:
        self._assert_open()
        rl.clear_background(rl.BLACK)
        pause_background = self.state.pause_background
        if pause_background is not None:
            pause_background.draw_pause_background()
        elif self._ground is not None:
            self._ground.draw(menu_ground_camera(self.state))
        _draw_screen_fade(self.state)

        assets = self._assets
        assert assets is not None, "Database panel assets must be loaded before draw()"

        screen_width = float(self.state.config.screen_width)
        scale = 1.0
        fx_detail = self.state.config.fx_detail(level=0, default=False)

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

        left_panel_pos_x = hs_left_panel_pos_x(screen_width)
        left_top_left = self._panel_top_left(pos=Vec2(left_panel_pos_x, LEFT_PANEL_POS_Y), scale=scale)
        right_panel_pos_x = hs_right_panel_pos_x(screen_width)
        right_top_left = self._panel_top_left(pos=Vec2(right_panel_pos_x, RIGHT_PANEL_POS_Y), scale=scale)
        left_panel_top_left = left_top_left.offset(dx=float(left_slide_x))
        right_panel_top_left = right_top_left.offset(dx=float(right_slide_x))

        draw_classic_menu_panel(
            assets.panel,
            dst=rl.Rectangle(left_panel_top_left.x, left_panel_top_left.y, panel_w, LEFT_PANEL_HEIGHT * scale),
            tint=rl.WHITE,
            shadow=fx_detail,
        )
        draw_classic_menu_panel(
            assets.panel,
            dst=rl.Rectangle(right_panel_top_left.x, right_panel_top_left.y, panel_w, RIGHT_PANEL_HEIGHT * scale),
            tint=rl.WHITE,
            shadow=fx_detail,
            flip_x=True,
        )

        font = self._ensure_small_font()
        self._draw_contents(left_panel_top_left, right_panel_top_left, scale=scale, font=font)

        textures = self._button_textures
        if textures is not None and (textures.button_md is not None or textures.button_sm is not None):
            back_pos = self._back_button_pos()
            back_w = button_width(font, self._back_button.label, scale=scale, force_wide=self._back_button.force_wide)
            button_draw(
                textures,
                font,
                self._back_button,
                pos=left_panel_top_left + back_pos * scale,
                width=back_w,
                scale=scale,
            )

        self._draw_sign()
        _draw_menu_cursor(self.state, pulse_time=self._cursor_pulse_time)

    def _back_button_pos(self) -> Vec2:
        raise NotImplementedError

    def _draw_contents(
        self,
        left_top_left: Vec2,
        right_top_left: Vec2,
        *,
        scale: float,
        font: SmallFontData,
    ) -> None:
        raise NotImplementedError

    def _update_content_interaction(self, *, left_top_left: Vec2, scale: float, mouse: rl.Vector2) -> None:
        return
