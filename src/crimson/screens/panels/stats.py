from __future__ import annotations

import datetime as dt

from crimson.screens.actions import Route, ScoreQuery, ScreenAction, ShowScores
from crimson.screens.chrome import draw_screen_background, draw_screen_cursor, ensure_menu_ground
from crimson.screens.transitions import ScreenTransition
from crimson.ui.animation import ui_element_anim
from crimson.ui.layout import menu_widescreen_y_shift
from crimson.ui.menu_chrome import draw_menu_sign, draw_ui_quad
from crimson.ui.menu_layout import (
    MENU_LABEL_ROW_HEIGHT,
    MENU_LABEL_ROW_STATISTICS,
    MENU_PANEL_OFFSET_X,
    MENU_PANEL_OFFSET_Y,
    MENU_PANEL_WIDTH,
)
from grim.assets import TextureId
from grim.audio import play_music, play_sfx, stop_music, update_audio
from grim.fonts.small import draw_small_text
from grim.geom import Vec2
from grim.rand import CrandLike
from grim.raylib_api import rl
from grim.sfx_map import SfxId
from grim.terrain_render import GroundRenderer

from ...game.types import GameState
from ...rng_caller_static import RngCallerStatic
from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, button_draw, button_update, button_width
from ..assets import require_runtime_resources
from ..transitions import _draw_screen_fade
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


def _stats_menu_easter_roll(current_roll: int, *, rng: CrandLike) -> int:
    if int(current_roll) != _STATS_EASTER_ROLL_UNSET:
        return int(current_roll)
    return int(rng.rand_tagged(RngCallerStatic.REWRITE_STATS_MENU_EASTER_ROLL) % 32)


def _is_orbes_volantes_day(today: dt.date) -> bool:
    return int(today.month) == 3 and int(today.day) == 3


def _format_playtime_text(game_sequence_ms: int, *, preserve_bugs: bool = False) -> str:
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
        self._ground: GroundRenderer | None = None

        self._cursor_pulse_time = 0.0
        self._widescreen_y_shift = 0.0
        self._transition = ScreenTransition()
        self._transition.duration_ms = PANEL_TIMELINE_START_MS

        self._btn_high_scores = UiButtonState("High scores", force_wide=True)
        self._btn_weapons = UiButtonState("Weapons", force_wide=True)
        self._btn_perks = UiButtonState("Perks", force_wide=True)
        self._btn_credits = UiButtonState("Credits", force_wide=True)
        self._btn_back = UiButtonState("Back", force_wide=False)

    def open(self) -> None:
        layout_w = float(self.state.config.display.width)
        self._widescreen_y_shift = menu_widescreen_y_shift(layout_w)
        self._ground = None if self.state.pause_background is not None else ensure_menu_ground(self.state)
        self._cursor_pulse_time = 0.0
        self._transition.reset()
        self._transition.duration_ms = PANEL_TIMELINE_START_MS

        self._btn_high_scores = UiButtonState("High scores", force_wide=True)
        self._btn_weapons = UiButtonState("Weapons", force_wide=True)
        self._btn_perks = UiButtonState("Perks", force_wide=True)
        self._btn_credits = UiButtonState("Credits", force_wide=True)
        self._btn_back = UiButtonState("Back", force_wide=False)

        if self.state.audio is not None:
            if self.state.audio.music.active_track != "shortie_monk":
                stop_music(self.state.audio)
            play_music(self.state.audio, "shortie_monk")
            play_sfx(self.state.audio, SfxId.UI_PANELCLICK)
        self._is_open = True

    def close(self) -> None:
        self._is_open = False
        self._ground = None

    def resume(self) -> None:
        self._transition.reset()
        self._transition.duration_ms = PANEL_TIMELINE_START_MS
        self._btn_high_scores = UiButtonState("High scores", force_wide=True)
        self._btn_weapons = UiButtonState("Weapons", force_wide=True)
        self._btn_perks = UiButtonState("Perks", force_wide=True)
        self._btn_credits = UiButtonState("Credits", force_wide=True)
        self._btn_back = UiButtonState("Back", force_wide=False)
        if self.state.audio is not None:
            play_sfx(self.state.audio, SfxId.UI_PANELCLICK)

    def take_action(self) -> ScreenAction | None:
        self._assert_open()
        return self._transition.take_action()

    def _assert_open(self) -> None:
        assert self._is_open, "StatisticsMenuView must be opened before use"

    def _panel_top_left(self, *, scale: float) -> Vec2:
        return Vec2(
            STATISTICS_PANEL_POS_X + MENU_PANEL_OFFSET_X * scale,
            STATISTICS_PANEL_POS_Y + self._widescreen_y_shift + MENU_PANEL_OFFSET_Y * scale,
        )

    def _begin_close_transition(self, action: ScreenAction) -> None:
        if self._transition.closing:
            return
        self._transition.begin(action)

    def update(self, dt: float) -> None:
        self._assert_open()
        if self.state.audio is not None:
            if not self._transition.closing:
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

        if not self._transition.advance(dt_ms):
            return

        interactive = self._transition.timeline_ms >= self._transition.duration_ms

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) and interactive:
            if self.state.audio is not None:
                play_sfx(self.state.audio, SfxId.UI_BUTTONCLICK)
            self._begin_close_transition(Route.MENU)
            return

        if not interactive:
            return

        scale = 0.9 if float(self.state.config.display.width) < 641.0 else 1.0
        panel_w = MENU_PANEL_WIDTH * scale
        _angle_rad, slide_x = ui_element_anim(
            self._transition.timeline_ms,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
            direction_flag=0,
        )
        panel_top_left = self._panel_top_left(scale=scale).offset(dx=float(slide_x))
        resources = require_runtime_resources(self.state)

        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        dt_ms_f = min(float(dt), 0.1) * 1000.0

        def _update_button(btn: UiButtonState, *, pos: Vec2) -> bool:
            w = button_width(resources, btn.label, scale=scale, force_wide=btn.force_wide)
            return button_update(btn, pos=pos, width=w, dt_ms=dt_ms_f, mouse=mouse, click=click)

        button_base = panel_top_left + Vec2(_BUTTON_X * scale, _BUTTON_Y0 * scale)
        if _update_button(self._btn_high_scores, pos=button_base.offset(dy=_BUTTON_STEP_Y * 0.0 * scale)):
            if self.state.audio is not None:
                play_sfx(self.state.audio, SfxId.UI_BUTTONCLICK)
            self._begin_close_transition(ShowScores(ScoreQuery.from_config(self.state.config)))
            return
        if _update_button(self._btn_weapons, pos=button_base.offset(dy=_BUTTON_STEP_Y * 1.0 * scale)):
            if self.state.audio is not None:
                play_sfx(self.state.audio, SfxId.UI_BUTTONCLICK)
            self._begin_close_transition(Route.WEAPONS)
            return
        if _update_button(self._btn_perks, pos=button_base.offset(dy=_BUTTON_STEP_Y * 2.0 * scale)):
            if self.state.audio is not None:
                play_sfx(self.state.audio, SfxId.UI_BUTTONCLICK)
            self._begin_close_transition(Route.PERKS)
            return
        if _update_button(self._btn_credits, pos=button_base.offset(dy=_BUTTON_STEP_Y * 3.0 * scale)):
            if self.state.audio is not None:
                play_sfx(self.state.audio, SfxId.UI_BUTTONCLICK)
            self._begin_close_transition(Route.CREDITS)
            return

        if _update_button(self._btn_back, pos=panel_top_left + Vec2(_BACK_BUTTON_X * scale, _BACK_BUTTON_Y * scale)):
            if self.state.audio is not None:
                play_sfx(self.state.audio, SfxId.UI_BUTTONCLICK)
            self._begin_close_transition(Route.MENU)
            return

    def draw(self) -> None:
        self._assert_open()
        draw_screen_background(self.state, self._ground)
        _draw_screen_fade(self.state)

        resources = require_runtime_resources(self.state)

        scale = 0.9 if float(self.state.config.display.width) < 641.0 else 1.0
        panel_w = MENU_PANEL_WIDTH * scale
        _angle_rad, slide_x = ui_element_anim(
            self._transition.timeline_ms,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
            direction_flag=0,
        )
        panel_top_left = self._panel_top_left(scale=scale).offset(dx=float(slide_x))
        dst = rl.Rectangle(
            panel_top_left.x,
            panel_top_left.y,
            panel_w,
            STATISTICS_PANEL_HEIGHT * scale,
        )
        shadows_enabled = self.state.config.display.shadows_enabled
        draw_classic_menu_panel(
            resources.texture(TextureId.UI_MENU_PANEL),
            dst=dst,
            tint=rl.WHITE,
            shadow=shadows_enabled,
        )

        # Title: full-size row from ui_itemTexts.jaz (128x32).
        label_tex = resources.texture(TextureId.UI_ITEM_TEXTS)
        row_h = float(MENU_LABEL_ROW_HEIGHT)
        src = rl.Rectangle(0.0, float(MENU_LABEL_ROW_STATISTICS) * row_h, float(label_tex.width), row_h)
        draw_ui_quad(
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
        font = resources.small_font
        draw_small_text(
            font,
            _format_playtime_text(
                int(self.state.status.play_time_ms),
                preserve_bugs=bool(self.state.preserve_bugs),
            ),
            panel_top_left + Vec2(_PLAYTIME_X * scale, _PLAYTIME_Y * scale),
            rl.Color(255, 255, 255, int(255 * 0.8)),
        )

        if (
            _is_orbes_volantes_day(dt.datetime.now(tz=dt.UTC).astimezone().date())
            and int(self.state.stats_menu_easter_egg_roll) == _STATS_EASTER_TRIGGER_ROLL
        ):
            self.state.stats_menu_easter_egg_roll = _STATS_EASTER_ROLL_UNSET
            x = float(self.state.rng.rand_tagged(RngCallerStatic.REWRITE_STATS_MENU_EASTER_TEXT_X) % 64 + 16)
            draw_small_text(font, _STATS_EASTER_TEXT, Vec2(x, _STATS_EASTER_TEXT_Y), rl.Color(51, 255, 153, 128))

        # Buttons.
        button_base = panel_top_left + Vec2(_BUTTON_X * scale, _BUTTON_Y0 * scale)
        for i, btn in enumerate((self._btn_high_scores, self._btn_weapons, self._btn_perks, self._btn_credits)):
            w = button_width(resources, btn.label, scale=scale, force_wide=btn.force_wide)
            button_draw(
                resources,
                btn,
                pos=button_base.offset(dy=_BUTTON_STEP_Y * float(i) * scale),
                width=w,
                scale=scale,
            )

        back_w = button_width(resources, self._btn_back.label, scale=scale, force_wide=self._btn_back.force_wide)
        button_draw(
            resources,
            self._btn_back,
            pos=panel_top_left + Vec2(_BACK_BUTTON_X * scale, _BACK_BUTTON_Y * scale),
            width=back_w,
            scale=scale,
        )

        draw_menu_sign(
            require_runtime_resources(self.state),
            width=self.state.config.display.width,
            shadows=self.state.config.display.shadows_enabled,
        )
        draw_screen_cursor(resources=resources, pulse_time=self._cursor_pulse_time)
