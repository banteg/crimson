from __future__ import annotations

import datetime as dt
import random

import pyray as rl

from grim.audio import play_music, play_sfx, stop_music, update_audio
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font
from grim.geom import Vec2
from grim.terrain_render import GroundRenderer

from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, UiButtonTextureSet, button_draw, button_update, button_width
from ..assets import MenuAssets, _ensure_texture_cache, load_menu_assets
from ..menu import (
    MENU_LABEL_ROW_HEIGHT,
    MENU_LABEL_ROW_STATISTICS,
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
from ..types import GameState
from .base import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS


# Measured from ui_render_trace_oracle_1024x768.json (state_4:played for # hours # minutes, timeline=300).
STATISTICS_PANEL_POS_X = -89.0
STATISTICS_PANEL_POS_Y = 185.0
STATISTICS_PANEL_HEIGHT = 378.0

# Child layout inside the panel (relative to panel top-left).
_TITLE_X = 290.0
_TITLE_Y = 52.0
_TITLE_W = 128.0
_TITLE_H = 32.0

_BUTTON_X = 270.0
_BUTTON_Y0 = 104.0
_BUTTON_STEP_Y = 34.0

_BACK_BUTTON_X = 394.0
_BACK_BUTTON_Y = 290.0

_PLAYTIME_X = 204.0
_PLAYTIME_Y = 334.0

_STATS_EASTER_ROLL_UNSET = -1
_STATS_EASTER_TRIGGER_ROLL = 3
_STATS_EASTER_TEXT = "Orbes Volantes Exstare"
_STATS_EASTER_TEXT_Y = 5.0


def _stats_menu_easter_roll(current_roll: int, *, rng: random.Random) -> int:
    if int(current_roll) != _STATS_EASTER_ROLL_UNSET:
        return int(current_roll)
    return int(rng.randrange(32))


def _is_orbes_volantes_day(today: dt.date) -> bool:
    return int(today.month) == 3 and int(today.day) == 3


def _format_playtime_text(game_sequence_ms: int) -> str:
    total_minutes = (max(0, int(game_sequence_ms)) // 1000) // 60
    hours = total_minutes // 60
    minutes = total_minutes % 60
    return f"played for {hours} hours {minutes} minutes"


class StatisticsMenuView:
    """
    Classic "Statistics" menu (state_id=4).

    This is a small hub panel with buttons for:
      - High scores
      - Weapons / Perks databases
      - Credits
    """

    def __init__(self, state: GameState) -> None:
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

        self._btn_high_scores = UiButtonState("High scores", force_wide=True)
        self._btn_weapons = UiButtonState("Weapons", force_wide=True)
        self._btn_perks = UiButtonState("Perks", force_wide=True)
        self._btn_credits = UiButtonState("Credits", force_wide=True)
        self._btn_back = UiButtonState("Back", force_wide=False)

    def open(self) -> None:
        layout_w = float(self.state.config.screen_width)
        self._widescreen_y_shift = MenuView._menu_widescreen_y_shift(layout_w)
        self._assets = load_menu_assets(self.state)
        self._ground = None if self.state.pause_background is not None else ensure_menu_ground(self.state)
        self._small_font = None
        self._cursor_pulse_time = 0.0
        self._action = None
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._closing = False
        self._close_action = None
        self._pending_action = None

        cache = _ensure_texture_cache(self.state)
        button_md = cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture
        button_sm = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture
        self._button_textures = UiButtonTextureSet(button_sm=button_sm, button_md=button_md)

        self._btn_high_scores = UiButtonState("High scores", force_wide=True)
        self._btn_weapons = UiButtonState("Weapons", force_wide=True)
        self._btn_perks = UiButtonState("Perks", force_wide=True)
        self._btn_credits = UiButtonState("Credits", force_wide=True)
        self._btn_back = UiButtonState("Back", force_wide=False)

        if self.state.audio is not None:
            if self.state.audio.music.active_track != "shortie_monk":
                stop_music(self.state.audio)
            play_music(self.state.audio, "shortie_monk")
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
        self._action = None
        self._closing = False
        self._close_action = None
        self._pending_action = None

    def reopen_from_child(self) -> None:
        self._action = None
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._closing = False
        self._close_action = None
        self._pending_action = None
        self._btn_high_scores = UiButtonState("High scores", force_wide=True)
        self._btn_weapons = UiButtonState("Weapons", force_wide=True)
        self._btn_perks = UiButtonState("Perks", force_wide=True)
        self._btn_credits = UiButtonState("Credits", force_wide=True)
        self._btn_back = UiButtonState("Back", force_wide=False)
        if self.state.audio is not None:
            play_sfx(self.state.audio, "sfx_ui_panelclick", rng=self.state.rng)

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
        assert self._is_open, "StatisticsMenuView must be opened before use"

    def _ensure_small_font(self) -> SmallFontData:
        if self._small_font is not None:
            return self._small_font
        missing_assets: list[str] = []
        self._small_font = load_small_font(self.state.assets_dir, missing_assets)
        return self._small_font

    def _panel_top_left(self, *, scale: float) -> Vec2:
        return Vec2(
            STATISTICS_PANEL_POS_X + MENU_PANEL_OFFSET_X * scale,
            STATISTICS_PANEL_POS_Y + self._widescreen_y_shift + MENU_PANEL_OFFSET_Y * scale,
        )

    def _begin_close_transition(self, action: str) -> None:
        if self._closing:
            return
        self._closing = True
        self._close_action = action

    def update(self, dt: float) -> None:
        self._assert_open()
        if self.state.audio is not None:
            if not self._closing:
                play_music(self.state.audio, "shortie_monk")
            update_audio(self.state.audio, dt)
        self.state.stats_menu_easter_egg_roll = _stats_menu_easter_roll(
            self.state.stats_menu_easter_egg_roll,
            rng=self.state.rng,
        )
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
        interactive = self._timeline_ms >= self._timeline_max_ms

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) and interactive:
            if self.state.audio is not None:
                play_sfx(self.state.audio, "sfx_ui_buttonclick", rng=self.state.rng)
            self._begin_close_transition("back_to_menu")
            return

        textures = self._button_textures
        if textures is None or (textures.button_md is None and textures.button_sm is None):
            return
        if not interactive:
            return

        scale = 0.9 if float(self.state.config.screen_width) < 641.0 else 1.0
        panel_w = MENU_PANEL_WIDTH * scale
        _angle_rad, slide_x = MenuView._ui_element_anim(
            self,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
            direction_flag=0,
        )
        panel_top_left = self._panel_top_left(scale=scale).offset(dx=float(slide_x))
        font = self._ensure_small_font()

        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        dt_ms_f = min(float(dt), 0.1) * 1000.0

        def _update_button(btn: UiButtonState, *, pos: Vec2) -> bool:
            w = button_width(font, btn.label, scale=scale, force_wide=btn.force_wide)
            return button_update(btn, pos=pos, width=w, dt_ms=dt_ms_f, mouse=mouse, click=click)

        button_base = panel_top_left + Vec2(_BUTTON_X * scale, _BUTTON_Y0 * scale)
        if _update_button(self._btn_high_scores, pos=button_base.offset(dy=_BUTTON_STEP_Y * 0.0 * scale)):
            if self.state.audio is not None:
                play_sfx(self.state.audio, "sfx_ui_buttonclick", rng=self.state.rng)
            self._begin_close_transition("open_high_scores")
            return
        if _update_button(self._btn_weapons, pos=button_base.offset(dy=_BUTTON_STEP_Y * 1.0 * scale)):
            if self.state.audio is not None:
                play_sfx(self.state.audio, "sfx_ui_buttonclick", rng=self.state.rng)
            self._begin_close_transition("open_weapon_database")
            return
        if _update_button(self._btn_perks, pos=button_base.offset(dy=_BUTTON_STEP_Y * 2.0 * scale)):
            if self.state.audio is not None:
                play_sfx(self.state.audio, "sfx_ui_buttonclick", rng=self.state.rng)
            self._begin_close_transition("open_perk_database")
            return
        if _update_button(self._btn_credits, pos=button_base.offset(dy=_BUTTON_STEP_Y * 3.0 * scale)):
            if self.state.audio is not None:
                play_sfx(self.state.audio, "sfx_ui_buttonclick", rng=self.state.rng)
            self._begin_close_transition("open_credits")
            return

        if _update_button(self._btn_back, pos=panel_top_left + Vec2(_BACK_BUTTON_X * scale, _BACK_BUTTON_Y * scale)):
            if self.state.audio is not None:
                play_sfx(self.state.audio, "sfx_ui_buttonclick", rng=self.state.rng)
            self._begin_close_transition("back_to_menu")
            return

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
        assert assets is not None, "StatisticsMenuView assets must be loaded before draw()"

        scale = 0.9 if float(self.state.config.screen_width) < 641.0 else 1.0
        panel_w = MENU_PANEL_WIDTH * scale
        _angle_rad, slide_x = MenuView._ui_element_anim(
            self,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
            direction_flag=0,
        )
        panel_top_left = self._panel_top_left(scale=scale).offset(dx=float(slide_x))
        dst = rl.Rectangle(
            panel_top_left.x, panel_top_left.y, panel_w, STATISTICS_PANEL_HEIGHT * scale
        )
        fx_detail = self.state.config.fx_detail(level=0, default=False)
        draw_classic_menu_panel(assets.panel, dst=dst, tint=rl.WHITE, shadow=fx_detail)

        # Title: full-size row from ui_itemTexts.jaz (128x32).
        label_tex = assets.labels
        row_h = float(MENU_LABEL_ROW_HEIGHT)
        src = rl.Rectangle(0.0, float(MENU_LABEL_ROW_STATISTICS) * row_h, float(label_tex.width), row_h)
        MenuView._draw_ui_quad(
            texture=label_tex,
            src=src,
            dst=rl.Rectangle(
                panel_top_left.x + _TITLE_X * scale,
                panel_top_left.y + _TITLE_Y * scale,
                _TITLE_W * scale,
                _TITLE_H * scale,
            ),
            origin=rl.Vector2(0.0, 0.0),
            rotation_deg=0.0,
            tint=rl.WHITE,
        )

        # "played for # hours # minutes"
        font = self._ensure_small_font()
        draw_small_text(
            font,
            _format_playtime_text(int(self.state.status.game_sequence_id)),
            panel_top_left + Vec2(_PLAYTIME_X * scale, _PLAYTIME_Y * scale),
            1.0 * scale,
            rl.Color(255, 255, 255, int(255 * 0.8)),
        )

        if _is_orbes_volantes_day(dt.date.today()) and int(self.state.stats_menu_easter_egg_roll) == _STATS_EASTER_TRIGGER_ROLL:
            self.state.stats_menu_easter_egg_roll = _STATS_EASTER_ROLL_UNSET
            x = float(self.state.rng.randrange(64) + 16)
            draw_small_text(
                font,
                _STATS_EASTER_TEXT,
                Vec2(x, _STATS_EASTER_TEXT_Y),
                1.0,
                rl.Color(51, 255, 153, 128),
            )

        # Buttons.
        textures = self._button_textures
        if textures is not None and (textures.button_md is not None or textures.button_sm is not None):
            button_base = panel_top_left + Vec2(_BUTTON_X * scale, _BUTTON_Y0 * scale)
            for i, btn in enumerate((self._btn_high_scores, self._btn_weapons, self._btn_perks, self._btn_credits)):
                w = button_width(font, btn.label, scale=scale, force_wide=btn.force_wide)
                button_draw(
                    textures,
                    font,
                    btn,
                    pos=button_base.offset(dy=_BUTTON_STEP_Y * float(i) * scale),
                    width=w,
                    scale=scale,
                )

            back_w = button_width(font, self._btn_back.label, scale=scale, force_wide=self._btn_back.force_wide)
            button_draw(
                textures,
                font,
                self._btn_back,
                pos=panel_top_left + Vec2(_BACK_BUTTON_X * scale, _BACK_BUTTON_Y * scale),
                width=back_w,
                scale=scale,
            )

        self._draw_sign(scale=scale)
        _draw_menu_cursor(self.state, pulse_time=self._cursor_pulse_time)

    def _draw_sign(self, *, scale: float) -> None:
        assets = self._assets
        assert assets is not None, "StatisticsMenuView assets must be loaded before drawing sign"
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
