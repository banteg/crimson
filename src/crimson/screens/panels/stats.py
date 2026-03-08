from __future__ import annotations

import datetime as dt

from grim.assets import TextureId
from grim.fonts.small import draw_small_text
from grim.geom import Vec2
from grim.rand import Crand
from grim.raylib_api import rl

from ...game.types import GameState
from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, button_draw, button_update, button_width
from ..assets import require_runtime_resources
from ..chrome import (
    MENU_LABEL_ROW_HEIGHT,
    MENU_LABEL_ROW_STATISTICS,
    ActionDispatchPolicy,
    BackdropPolicy,
    ChromeSpec,
    MusicPolicy,
    SignPolicy,
)
from .base import (
    _ChromePanelView,
)

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


def _stats_menu_easter_roll(current_roll: int, *, rng: Crand) -> int:
    if int(current_roll) != _STATS_EASTER_ROLL_UNSET:
        return int(current_roll)
    return int(rng.rand() % 32)


def _is_orbes_volantes_day(today: dt.date) -> bool:
    return int(today.month) == 3 and int(today.day) == 3


def _format_playtime_text(game_sequence_ms: int, *, preserve_bugs: bool = False) -> str:
    total_minutes = (max(0, int(game_sequence_ms)) // 1000) // 60
    hours = total_minutes // 60
    minutes = total_minutes % 60
    if bool(preserve_bugs):
        return f"played for {hours} hours {minutes} minutes"
    hour_label = "hour" if hours == 1 else "hours"
    minute_label = "minute" if minutes == 1 else "minutes"
    return f"played for {hours} {hour_label} {minutes} {minute_label}"


class StatisticsMenuView(_ChromePanelView):
    """
    Classic "Statistics" menu (state_id=4).

    This is a small hub panel with buttons for:
      - High scores
      - Weapons / Perks databases
      - Credits
    """

    def __init__(self, state: GameState) -> None:
        super().__init__(
            state,
            chrome_spec=ChromeSpec(
                backdrop=BackdropPolicy(),
                music=MusicPolicy(
                    primary_track="shortie_monk",
                    refresh_while_open=True,
                    stop_if_track_mismatch=True,
                ),
                sign=SignPolicy(),
                dispatch=ActionDispatchPolicy(mode="pending_rearm"),
                open_sfx="sfx_ui_panelclick",
                open_sfx_mode="on_open",
                close_sfx="sfx_ui_buttonclick",
            ),
        )
        self._btn_high_scores = UiButtonState("High scores", force_wide=True)
        self._btn_weapons = UiButtonState("Weapons", force_wide=True)
        self._btn_perks = UiButtonState("Perks", force_wide=True)
        self._btn_credits = UiButtonState("Credits", force_wide=True)
        self._btn_back = UiButtonState("Back", force_wide=False)

    def reopen_from_child(self) -> None:
        self._reset_view_state()
        self._rearm_view(play_open_sfx=True)

    def _reset_view_state(self) -> None:
        self._btn_high_scores = UiButtonState("High scores", force_wide=True)
        self._btn_weapons = UiButtonState("Weapons", force_wide=True)
        self._btn_perks = UiButtonState("Perks", force_wide=True)
        self._btn_credits = UiButtonState("Credits", force_wide=True)
        self._btn_back = UiButtonState("Back", force_wide=False)

    def _update_button(self, btn: UiButtonState, *, pos: Vec2, scale: float, mouse: rl.Vector2, click: bool, dt_ms: float) -> bool:
        resources = require_runtime_resources(self.state)
        width = button_width(resources, btn.label, scale=scale, force_wide=btn.force_wide)
        return button_update(btn, pos=pos, width=width, dt_ms=dt_ms, mouse=mouse, click=click)

    def update(self, dt: float) -> None:
        self._assert_open()
        tick = self._chrome.update(dt)
        self.state.stats_menu_easter_egg_roll = _stats_menu_easter_roll(
            self.state.stats_menu_easter_egg_roll,
            rng=self.state.rng,
        )
        if self._chrome.chrome.closing:
            return

        if not tick.interactive:
            return

        frame = self._panel_frame(
            panel_pos=Vec2(STATISTICS_PANEL_POS_X, STATISTICS_PANEL_POS_Y),
            panel_height=STATISTICS_PANEL_HEIGHT,
        )
        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        dt_ms = min(float(dt), 0.1) * 1000.0

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._begin_close_transition("back_to_menu")
            return

        button_base = frame.panel_top_left + Vec2(_BUTTON_X * frame.scale, _BUTTON_Y0 * frame.scale)
        if self._update_button(
            self._btn_high_scores,
            pos=button_base.offset(dy=_BUTTON_STEP_Y * 0.0 * frame.scale),
            scale=frame.scale,
            mouse=mouse,
            click=bool(click),
            dt_ms=dt_ms,
        ):
            self._begin_close_transition("open_high_scores")
            return
        if self._update_button(
            self._btn_weapons,
            pos=button_base.offset(dy=_BUTTON_STEP_Y * 1.0 * frame.scale),
            scale=frame.scale,
            mouse=mouse,
            click=bool(click),
            dt_ms=dt_ms,
        ):
            self._begin_close_transition("open_weapon_database")
            return
        if self._update_button(
            self._btn_perks,
            pos=button_base.offset(dy=_BUTTON_STEP_Y * 2.0 * frame.scale),
            scale=frame.scale,
            mouse=mouse,
            click=bool(click),
            dt_ms=dt_ms,
        ):
            self._begin_close_transition("open_perk_database")
            return
        if self._update_button(
            self._btn_credits,
            pos=button_base.offset(dy=_BUTTON_STEP_Y * 3.0 * frame.scale),
            scale=frame.scale,
            mouse=mouse,
            click=bool(click),
            dt_ms=dt_ms,
        ):
            self._begin_close_transition("open_credits")
            return
        if self._update_button(
            self._btn_back,
            pos=frame.panel_top_left + Vec2(_BACK_BUTTON_X * frame.scale, _BACK_BUTTON_Y * frame.scale),
            scale=frame.scale,
            mouse=mouse,
            click=bool(click),
            dt_ms=dt_ms,
        ):
            self._begin_close_transition("back_to_menu")

    def draw(self) -> None:
        self._assert_open()
        self._draw_background()
        self._chrome.draw_fade()
        resources = require_runtime_resources(self.state)
        frame = self._panel_frame(
            panel_pos=Vec2(STATISTICS_PANEL_POS_X, STATISTICS_PANEL_POS_Y),
            panel_height=STATISTICS_PANEL_HEIGHT,
        )
        dst = rl.Rectangle(
            frame.panel_top_left.x,
            frame.panel_top_left.y,
            frame.panel_width,
            frame.panel_height,
        )
        fx_detail = self.state.config.fx_detail(level=0, default=False)
        draw_classic_menu_panel(resources.texture(TextureId.UI_MENU_PANEL), dst=dst, tint=rl.WHITE, shadow=fx_detail)

        label_tex = resources.texture(TextureId.UI_ITEM_TEXTS)
        row_h = float(MENU_LABEL_ROW_HEIGHT)
        src = rl.Rectangle(0.0, float(MENU_LABEL_ROW_STATISTICS) * row_h, float(label_tex.width), row_h)
        rl.draw_texture_pro(
            label_tex,
            src,
            rl.Rectangle(
                frame.panel_top_left.x + _TITLE_X * frame.scale,
                frame.panel_top_left.y + _TITLE_Y * frame.scale,
                _TITLE_W * frame.scale,
                _TITLE_H * frame.scale,
            ),
            rl.Vector2(0.0, 0.0),
            0.0,
            rl.WHITE,
        )

        font = resources.small_font
        draw_small_text(
            font,
            _format_playtime_text(
                int(self.state.status.game_sequence_id),
                preserve_bugs=bool(self.state.preserve_bugs),
            ),
            frame.panel_top_left + Vec2(_PLAYTIME_X * frame.scale, _PLAYTIME_Y * frame.scale),
            rl.Color(255, 255, 255, int(255 * 0.8)),
        )

        if _is_orbes_volantes_day(dt.date.today()) and int(self.state.stats_menu_easter_egg_roll) == _STATS_EASTER_TRIGGER_ROLL:
            self.state.stats_menu_easter_egg_roll = _STATS_EASTER_ROLL_UNSET
            x = float(self.state.rng.rand() % 64 + 16)
            draw_small_text(font, _STATS_EASTER_TEXT, Vec2(x, _STATS_EASTER_TEXT_Y), rl.Color(51, 255, 153, 128))

        button_base = frame.panel_top_left + Vec2(_BUTTON_X * frame.scale, _BUTTON_Y0 * frame.scale)
        for index, btn in enumerate((self._btn_high_scores, self._btn_weapons, self._btn_perks, self._btn_credits)):
            width = button_width(resources, btn.label, scale=frame.scale, force_wide=btn.force_wide)
            button_draw(
                resources,
                btn,
                pos=button_base.offset(dy=_BUTTON_STEP_Y * float(index) * frame.scale),
                width=width,
                scale=frame.scale,
            )

        back_w = button_width(resources, self._btn_back.label, scale=frame.scale, force_wide=self._btn_back.force_wide)
        button_draw(
            resources,
            self._btn_back,
            pos=frame.panel_top_left + Vec2(_BACK_BUTTON_X * frame.scale, _BACK_BUTTON_Y * frame.scale),
            width=back_w,
            scale=frame.scale,
        )

        self._draw_sign()
        self._draw_cursor()
