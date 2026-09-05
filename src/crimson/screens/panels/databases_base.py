from __future__ import annotations

from crimson.screens.actions import Route, ScreenAction
from crimson.screens.chrome import draw_screen_background, draw_screen_cursor, ensure_menu_ground
from crimson.screens.transitions import ScreenTransition
from crimson.ui.animation import ui_element_anim
from crimson.ui.layout import menu_widescreen_y_shift
from crimson.ui.menu_chrome import draw_menu_sign
from crimson.ui.menu_layout import (
    MENU_PANEL_OFFSET_X,
    MENU_PANEL_OFFSET_Y,
    MENU_PANEL_WIDTH,
)
from grim.assets import TextureId
from grim.audio import play_sfx, update_audio
from grim.fonts.small import SmallFontData
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.sfx_map import SfxId
from grim.terrain_render import GroundRenderer

from ...game.types import GameState
from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, button_draw, button_update, button_width
from ..assets import require_runtime_resources
from ..high_scores_layout import hs_left_panel_pos_x, hs_right_panel_pos_x
from ..transitions import _draw_screen_fade
from .base import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS

# Shared panel layout (state_14/15/16 in the oracle): tall left panel + short right panel.
LEFT_PANEL_POS_Y = 185.0
LEFT_PANEL_HEIGHT = 378.0
RIGHT_PANEL_POS_Y = 200.0
RIGHT_PANEL_HEIGHT = 254.0


class _DatabaseBaseView:
    def __init__(self, state: GameState) -> None:
        self.state = state
        self._is_open = False
        self._ground: GroundRenderer | None = None

        self._cursor_pulse_time = 0.0
        self._widescreen_y_shift = 0.0
        self._transition = ScreenTransition()
        self._transition.duration_ms = PANEL_TIMELINE_START_MS

        self._back_button = UiButtonState("Back", force_wide=False)

    def open(self) -> None:
        layout_w = float(self.state.config.display.width)
        self._widescreen_y_shift = menu_widescreen_y_shift(layout_w)
        self._ground = None if self.state.pause_background is not None else ensure_menu_ground(self.state)
        self._cursor_pulse_time = 0.0
        self._transition.reset()
        self._transition.duration_ms = PANEL_TIMELINE_START_MS

        self._back_button = UiButtonState("Back", force_wide=False)

        if self.state.audio is not None:
            play_sfx(self.state.audio, SfxId.UI_PANELCLICK)
        self._is_open = True

    def close(self) -> None:
        self._is_open = False
        self._ground = None

    def take_action(self) -> ScreenAction | None:
        self._assert_open()
        return self._transition.take_action()

    def _assert_open(self) -> None:
        assert self._is_open, f"{self.__class__.__name__} must be opened before use"

    def _panel_top_left(self, *, pos: Vec2, scale: float) -> Vec2:
        return Vec2(
            pos.x + MENU_PANEL_OFFSET_X * scale,
            pos.y + self._widescreen_y_shift + MENU_PANEL_OFFSET_Y * scale,
        )

    def _begin_close_transition(self, action: ScreenAction) -> None:
        if self._transition.closing:
            return
        self._transition.begin(action)

    def update(self, dt: float) -> None:
        self._assert_open()
        if self.state.audio is not None:
            update_audio(self.state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        self._cursor_pulse_time += min(float(dt), 0.1) * 1.1

        dt_ms = int(min(float(dt), 0.1) * 1000.0)
        if not self._transition.advance(dt_ms):
            return

        enabled = self._transition.timeline_ms >= self._transition.duration_ms

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) and enabled:
            if self.state.audio is not None:
                play_sfx(self.state.audio, SfxId.UI_BUTTONCLICK)
            self._begin_close_transition(Route.BACK)
            return

        if not enabled:
            return

        screen_width = float(self.state.config.display.width)
        scale = 1.0
        left_panel_pos_x = hs_left_panel_pos_x(screen_width)
        left_top_left = self._panel_top_left(pos=Vec2(left_panel_pos_x, LEFT_PANEL_POS_Y), scale=scale)
        resources = require_runtime_resources(self.state)

        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        self._update_content_interaction(left_top_left=left_top_left, scale=scale, mouse=mouse)

        back_pos = self._back_button_pos()
        back_w = button_width(resources, self._back_button.label, scale=scale, force_wide=self._back_button.force_wide)
        if button_update(
            self._back_button,
            pos=left_top_left + back_pos * scale,
            width=back_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            if self.state.audio is not None:
                play_sfx(self.state.audio, SfxId.UI_BUTTONCLICK)
            self._begin_close_transition(Route.BACK)

    def draw(self) -> None:
        self._assert_open()
        draw_screen_background(self.state, self._ground)
        _draw_screen_fade(self.state)

        screen_width = float(self.state.config.display.width)
        scale = 1.0
        shadows_enabled = self.state.config.display.shadows_enabled

        panel_w = MENU_PANEL_WIDTH * scale
        _angle_rad, left_slide_x = ui_element_anim(
            self._transition.timeline_ms,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
            direction_flag=0,
        )
        _angle_rad, right_slide_x = ui_element_anim(
            self._transition.timeline_ms,
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
            require_runtime_resources(self.state).texture(TextureId.UI_MENU_PANEL),
            dst=rl.Rectangle(left_panel_top_left.x, left_panel_top_left.y, panel_w, LEFT_PANEL_HEIGHT * scale),
            tint=rl.WHITE,
            shadow=shadows_enabled,
        )
        draw_classic_menu_panel(
            require_runtime_resources(self.state).texture(TextureId.UI_MENU_PANEL),
            dst=rl.Rectangle(right_panel_top_left.x, right_panel_top_left.y, panel_w, RIGHT_PANEL_HEIGHT * scale),
            tint=rl.WHITE,
            shadow=shadows_enabled,
            flip_x=True,
        )

        resources = require_runtime_resources(self.state)
        font = resources.small_font
        self._draw_contents(left_panel_top_left, right_panel_top_left, scale=scale, font=font)

        back_pos = self._back_button_pos()
        back_w = button_width(resources, self._back_button.label, scale=scale, force_wide=self._back_button.force_wide)
        button_draw(
            resources,
            self._back_button,
            pos=left_panel_top_left + back_pos * scale,
            width=back_w,
            scale=scale,
        )

        draw_menu_sign(
            require_runtime_resources(self.state),
            width=self.state.config.display.width,
            shadows=self.state.config.display.shadows_enabled,
            locked=True,
            timeline_ms=self._transition.timeline_ms,
        )
        draw_screen_cursor(resources=resources, pulse_time=self._cursor_pulse_time)

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
