from __future__ import annotations

import pyray as rl

from grim.audio import play_sfx, update_audio
from grim.geom import Vec2
from grim.terrain_render import GroundRenderer
from grim.fonts.small import SmallFontData, load_small_font

from ...frontend.assets import MenuAssets, _ensure_texture_cache, load_menu_assets
from ...frontend.high_scores_layout import (
    HS_BACK_BUTTON_X,
    HS_BACK_BUTTON_Y,
    HS_BUTTON_STEP_Y,
    HS_BUTTON_X,
    HS_BUTTON_Y0,
    HS_LEFT_PANEL_HEIGHT,
    HS_LEFT_PANEL_POS_X,
    HS_LEFT_PANEL_POS_Y,
    HS_RIGHT_PANEL_HEIGHT,
    HS_RIGHT_PANEL_POS_Y,
    hs_right_panel_pos_x,
)
from ...frontend.menu import (
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
from ...frontend.panels.base import FADE_TO_GAME_ACTIONS, PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS
from ...frontend.transitions import _draw_screen_fade
from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, UiButtonTextureSet, button_update, button_width
from ..types import GameState, HighScoresRequest
from .main_panel import draw_main_panel
from .records import load_records, resolve_request
from .right_panel import draw_right_panel


class HighScoresView:
    def __init__(self, state: GameState) -> None:
        self.state = state
        self._assets: MenuAssets | None = None
        self._ground: GroundRenderer | None = None
        self._action: str | None = None
        self._cursor_pulse_time = 0.0
        self._widescreen_y_shift = 0.0
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._closing = False
        self._close_action: str | None = None
        self._small_font: SmallFontData | None = None
        self._button_tex: rl.Texture | None = None
        self._button_textures: UiButtonTextureSet | None = None
        self._check_on: rl.Texture | None = None
        self._drop_off: rl.Texture | None = None
        self._arrow_tex: rl.Texture | None = None
        self._wicons_tex: rl.Texture | None = None
        self._clock_table_tex: rl.Texture | None = None
        self._clock_pointer_tex: rl.Texture | None = None
        self._update_button = UiButtonState("Update scores", force_wide=True)
        self._play_button = UiButtonState("Play a game", force_wide=True)
        self._back_button = UiButtonState("Back", force_wide=False)

        self._request: HighScoresRequest | None = None
        self._records: list = []
        self._scroll_index = 0

    def open(self) -> None:
        layout_w = float(self.state.config.screen_width)
        self._widescreen_y_shift = MenuView._menu_widescreen_y_shift(layout_w)
        self._action = None
        self._assets = load_menu_assets(self.state)
        self._ground = None if self.state.pause_background is not None else ensure_menu_ground(self.state)
        self._cursor_pulse_time = 0.0
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._closing = False
        self._close_action = None
        self._small_font = None
        self._scroll_index = 0
        self._button_textures = None
        self._update_button = UiButtonState("Update scores", force_wide=True)
        self._play_button = UiButtonState("Play a game", force_wide=True)
        self._back_button = UiButtonState("Back", force_wide=False)

        cache = _ensure_texture_cache(self.state)
        self._button_tex = cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture
        button_sm = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture
        self._button_textures = UiButtonTextureSet(button_sm=button_sm, button_md=self._button_tex)
        self._check_on = cache.get_or_load("ui_checkOn", "ui/ui_checkOn.jaz").texture
        self._drop_off = cache.get_or_load("ui_dropOff", "ui/ui_dropDownOff.jaz").texture
        self._arrow_tex = cache.get_or_load("ui_arrow", "ui/ui_arrow.jaz").texture
        self._wicons_tex = cache.get_or_load("ui_wicons", "ui/ui_wicons.jaz").texture
        self._clock_table_tex = cache.get_or_load("ui_clockTable", "ui/ui_clockTable.jaz").texture
        self._clock_pointer_tex = cache.get_or_load("ui_clockPointer", "ui/ui_clockPointer.jaz").texture

        request = resolve_request(self.state)
        self._request = request
        self._records = load_records(self.state, request)
        if self.state.audio is not None:
            play_sfx(self.state.audio, "sfx_ui_panelclick", rng=self.state.rng)

    def close(self) -> None:
        if self._small_font is not None:
            rl.unload_texture(self._small_font.texture)
            self._small_font = None
        self._wicons_tex = None
        self._clock_table_tex = None
        self._clock_pointer_tex = None
        self._assets = None
        self._button_tex = None
        self._button_textures = None
        self._check_on = None
        self._drop_off = None
        self._arrow_tex = None
        self._request = None
        self._records = []
        self._scroll_index = 0
        self._closing = False
        self._close_action = None

    def _panel_top_left(self, *, pos: Vec2, scale: float) -> Vec2:
        return Vec2(
            pos.x + MENU_PANEL_OFFSET_X * scale,
            pos.y + self._widescreen_y_shift + MENU_PANEL_OFFSET_Y * scale,
        )

    def update(self, dt: float) -> None:
        if self.state.audio is not None:
            update_audio(self.state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        self._cursor_pulse_time += min(dt, 0.1) * 1.1

        dt_ms = int(min(float(dt), 0.1) * 1000.0)
        if self._closing:
            if dt_ms > 0 and self._action is None:
                self._timeline_ms -= dt_ms
                if self._timeline_ms < 0 and self._close_action is not None:
                    self._action = self._close_action
                    self._close_action = None
            return
        if dt_ms > 0:
            self._timeline_ms = min(self._timeline_max_ms, int(self._timeline_ms + dt_ms))

        enabled = self._timeline_ms >= self._timeline_max_ms

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) and enabled:
            self._begin_close_transition("back_to_previous")
            return

        textures = self._button_textures
        if enabled and textures is not None and (textures.button_sm is not None or textures.button_md is not None):
            scale = 0.9 if float(self.state.config.screen_width) < 641.0 else 1.0
            font = self._ensure_small_font()
            panel_top_left = self._panel_top_left(pos=Vec2(HS_LEFT_PANEL_POS_X, HS_LEFT_PANEL_POS_Y), scale=scale)
            button_base_pos = panel_top_left + Vec2(HS_BUTTON_X * scale, HS_BUTTON_Y0 * scale)
            mouse = rl.get_mouse_position()
            click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
            w = button_width(font, self._update_button.label, scale=scale, force_wide=self._update_button.force_wide)
            if button_update(
                self._update_button,
                pos=button_base_pos,
                width=w,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ):
                # Reload scores from disk (no view transition).
                if self.state.audio is not None:
                    play_sfx(self.state.audio, "sfx_ui_buttonclick", rng=self.state.rng)
                self.open()
                return
            w = button_width(font, self._play_button.label, scale=scale, force_wide=self._play_button.force_wide)
            if button_update(
                self._play_button,
                pos=button_base_pos.offset(dy=HS_BUTTON_STEP_Y * scale),
                width=w,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ):
                self._begin_close_transition("open_play_game")
                return
            back_w = button_width(font, self._back_button.label, scale=scale, force_wide=self._back_button.force_wide)
            if button_update(
                self._back_button,
                pos=panel_top_left + Vec2(HS_BACK_BUTTON_X * scale, HS_BACK_BUTTON_Y * scale),
                width=back_w,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ):
                self._begin_close_transition("back_to_previous")
                return

        rows = 10
        max_scroll = max(0, len(self._records) - rows)

        if enabled:
            wheel = int(rl.get_mouse_wheel_move())
            if wheel:
                self._scroll_index = max(0, min(max_scroll, int(self._scroll_index) - wheel))

            if rl.is_key_pressed(rl.KeyboardKey.KEY_UP):
                self._scroll_index = max(0, int(self._scroll_index) - 1)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_DOWN):
                self._scroll_index = min(max_scroll, int(self._scroll_index) + 1)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_PAGE_UP):
                self._scroll_index = max(0, int(self._scroll_index) - rows)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_PAGE_DOWN):
                self._scroll_index = min(max_scroll, int(self._scroll_index) + rows)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_HOME):
                self._scroll_index = 0
            if rl.is_key_pressed(rl.KeyboardKey.KEY_END):
                self._scroll_index = max_scroll

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        pause_background = self.state.pause_background
        if pause_background is not None:
            pause_background.draw_pause_background(entity_alpha=self._world_entity_alpha())
        elif self._ground is not None:
            self._ground.draw(menu_ground_camera(self.state))
        _draw_screen_fade(self.state)

        assets = self._assets
        assert assets is not None, "HighScoresView assets must be loaded before draw()"

        font = self._ensure_small_font()
        request = self._request
        mode_id = int(request.game_mode_id) if request is not None else self.state.config.game_mode
        quest_major = int(request.quest_stage_major) if request is not None else 0
        quest_minor = int(request.quest_stage_minor) if request is not None else 0

        scale = 0.9 if float(self.state.config.screen_width) < 641.0 else 1.0
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

        left_top_left = self._panel_top_left(pos=Vec2(HS_LEFT_PANEL_POS_X, HS_LEFT_PANEL_POS_Y), scale=scale)
        right_panel_pos_x = hs_right_panel_pos_x(float(self.state.config.screen_width))
        right_top_left = self._panel_top_left(pos=Vec2(right_panel_pos_x, HS_RIGHT_PANEL_POS_Y), scale=scale)
        left_panel_top_left = left_top_left.offset(dx=float(left_slide_x))
        right_panel_top_left = right_top_left.offset(dx=float(right_slide_x))

        draw_classic_menu_panel(
            assets.panel,
            dst=rl.Rectangle(left_panel_top_left.x, left_panel_top_left.y, panel_w, HS_LEFT_PANEL_HEIGHT * scale),
            tint=rl.WHITE,
            shadow=fx_detail,
        )
        draw_classic_menu_panel(
            assets.panel,
            dst=rl.Rectangle(right_panel_top_left.x, right_panel_top_left.y, panel_w, HS_RIGHT_PANEL_HEIGHT * scale),
            tint=rl.WHITE,
            shadow=fx_detail,
            flip_x=True,
        )

        selected_rank = draw_main_panel(
            self,
            font=font,
            left_panel_top_left=left_panel_top_left,
            scale=scale,
            mode_id=mode_id,
            quest_major=quest_major,
            quest_minor=quest_minor,
            request=request,
        )

        draw_right_panel(
            self,
            font=font,
            right_top_left=right_panel_top_left,
            scale=scale,
            highlight_rank=selected_rank,
        )
        self._draw_sign(assets)
        _draw_menu_cursor(self.state, pulse_time=self._cursor_pulse_time)

    def _draw_sign(self, assets: MenuAssets) -> None:
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

    def _world_entity_alpha(self) -> float:
        if not self._closing:
            return 1.0
        span = PANEL_TIMELINE_START_MS - PANEL_TIMELINE_END_MS
        if span <= 0:
            return 0.0
        alpha = (float(self._timeline_ms) - PANEL_TIMELINE_END_MS) / float(span)
        if alpha < 0.0:
            return 0.0
        if alpha > 1.0:
            return 1.0
        return alpha

    def _begin_close_transition(self, action: str) -> None:
        if self._closing:
            return
        if action in FADE_TO_GAME_ACTIONS:
            self.state.screen_fade_alpha = 0.0
            self.state.screen_fade_ramp = True
        if self.state.audio is not None:
            play_sfx(self.state.audio, "sfx_ui_buttonclick", rng=self.state.rng)
        self._closing = True
        self._close_action = action

    def take_action(self) -> str | None:
        action = self._action
        self._action = None
        return action

    def _ensure_small_font(self) -> SmallFontData:
        if self._small_font is not None:
            return self._small_font
        missing_assets: list[str] = []
        self._small_font = load_small_font(self.state.assets_dir, missing_assets)
        return self._small_font

    def _visible_rows(self, font: SmallFontData) -> int:
        row_step = float(font.cell_size)
        table_top = 188.0 + row_step
        reserved_bottom = 96.0
        available = max(0.0, float(rl.get_screen_height()) - table_top - reserved_bottom)
        return max(1, int(available // row_step))


__all__ = ["HighScoresView"]
