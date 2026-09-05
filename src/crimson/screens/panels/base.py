from __future__ import annotations

from crimson.screens.actions import Route, ScreenAction, StartRun
from crimson.screens.chrome import draw_screen_background, draw_screen_cursor, ensure_menu_ground
from crimson.screens.transitions import ScreenTransition
from crimson.ui.animation import ui_element_anim
from crimson.ui.layout import menu_widescreen_y_shift
from crimson.ui.menu_chrome import draw_menu_sign, draw_ui_quad
from crimson.ui.menu_layout import (
    MENU_ITEM_OFFSET_X,
    MENU_ITEM_OFFSET_Y,
    MENU_LABEL_HEIGHT,
    MENU_LABEL_OFFSET_X,
    MENU_LABEL_OFFSET_Y,
    MENU_LABEL_ROW_BACK,
    MENU_LABEL_ROW_HEIGHT,
    MENU_LABEL_WIDTH,
    MENU_PANEL_HEIGHT,
    MENU_PANEL_OFFSET_X,
    MENU_PANEL_OFFSET_Y,
    MENU_PANEL_WIDTH,
    MenuEntry,
    label_alpha,
)
from crimson.ui.shadow import UI_SHADOW_OFFSET, draw_ui_quad_shadow
from grim.assets import TextureId
from grim.audio import play_sfx, update_audio
from grim.geom import Rect, Vec2
from grim.raylib_api import rl
from grim.sfx_map import SfxId
from grim.terrain_render import GroundRenderer

from ...game.types import GameState
from ...ui.menu_panel import draw_classic_menu_panel
from ..assets import require_runtime_resources
from ..transitions import _draw_screen_fade

PANEL_POS_X = -45.0
PANEL_POS_Y = 210.0
PANEL_BACK_POS_X = -55.0
PANEL_BACK_POS_Y = 430.0
PANEL_TIMELINE_START_MS = 300
PANEL_TIMELINE_END_MS = 0


class PanelMenuView:
    def __init__(
        self,
        state: GameState,
        *,
        title: str,
        body: str | None = None,
        panel_pos: Vec2 = Vec2(PANEL_POS_X, PANEL_POS_Y),
        panel_offset: Vec2 = Vec2(MENU_PANEL_OFFSET_X, MENU_PANEL_OFFSET_Y),
        panel_height: float = MENU_PANEL_HEIGHT,
        back_pos: Vec2 = Vec2(PANEL_BACK_POS_X, PANEL_BACK_POS_Y),
        back_action: ScreenAction = Route.MENU,
    ) -> None:
        self.state = state
        self._is_open = False
        self._title = title
        self._body_lines = (body or "").splitlines()
        self._panel_pos = panel_pos
        self._panel_offset = panel_offset
        self._panel_height = panel_height
        self._back_pos = back_pos
        self._back_action = back_action
        self._ground: GroundRenderer | None = None
        self._entry: MenuEntry | None = None
        self._hovered = False
        self._menu_screen_width = 0
        self._widescreen_y_shift = 0.0
        self._transition = ScreenTransition()
        self._transition.duration_ms = 0
        self._cursor_pulse_time = 0.0
        self._panel_open_sfx_played = False

    def open(self) -> None:
        layout_w = float(self.state.config.display.width)
        self._menu_screen_width = int(layout_w)
        self._widescreen_y_shift = menu_widescreen_y_shift(layout_w)
        self._entry = MenuEntry(slot=0, row=MENU_LABEL_ROW_BACK, y=self._back_pos.y)
        self._hovered = False
        self._transition.reset()
        self._transition.duration_ms = PANEL_TIMELINE_START_MS
        self._cursor_pulse_time = 0.0
        self._panel_open_sfx_played = False
        self._init_ground()
        self._is_open = True

    def resume(self) -> None:
        self._transition.reset()
        self._hovered = False
        self._panel_open_sfx_played = False

    def close(self) -> None:
        self._is_open = False
        self._ground = None

    def update(self, dt: float) -> None:
        if self._update_panel(dt):
            self._update_back_button(dt)

    def _update_panel(self, dt: float, *, play_open_sfx: bool = True) -> bool:
        """Advance presentation without consuming widget or navigation input."""
        self._assert_open()
        if self.state.audio is not None:
            update_audio(self.state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        self._cursor_pulse_time += min(dt, 0.1) * 1.1
        dt_ms = int(min(dt, 0.1) * 1000.0)
        if not self._transition.advance(dt_ms):
            return False

        if dt_ms > 0 and self._transition.timeline_ms >= self._transition.duration_ms:
            self.state.menu_sign_locked = True
            if play_open_sfx and (not self._panel_open_sfx_played) and (self.state.audio is not None):
                play_sfx(self.state.audio, SfxId.UI_PANELCLICK)
                self._panel_open_sfx_played = True

        return True

    def _update_back_button(self, dt: float, *, enabled: bool = True, enter: bool = True) -> None:
        dt_ms = int(min(dt, 0.1) * 1000.0)
        entry = self._entry
        if entry is None:
            return

        enabled = enabled and self._entry_enabled(entry)
        hovered = enabled and self._hovered_entry(entry)
        self._hovered = hovered

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) and enabled:
            self._begin_close_transition(self._back_action)
        if enter and rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER) and enabled:
            self._begin_close_transition(self._back_action)
        if enabled and hovered and rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
            self._begin_close_transition(self._back_action)

        if hovered:
            entry.hover_amount += dt_ms * 6
        else:
            entry.hover_amount -= dt_ms * 2
        entry.hover_amount = max(0, min(1000, entry.hover_amount))

        if entry.ready_timer_ms < 0x100:
            entry.ready_timer_ms = min(0x100, entry.ready_timer_ms + dt_ms)

    def draw(self) -> None:
        self._assert_open()
        draw_screen_background(self.state, self._ground)
        _draw_screen_fade(self.state)
        entry = self._entry
        assert entry is not None, "PanelMenuView entry must be initialized before draw()"
        self._draw_panel()
        self._draw_entry(entry)
        draw_menu_sign(
            require_runtime_resources(self.state),
            width=self.state.config.display.width,
            shadows=self.state.config.display.shadows_enabled,
            locked=True,
            timeline_ms=self._transition.timeline_ms,
        )
        self._draw_contents()
        draw_screen_cursor(
            resources=require_runtime_resources(self.state),
            pulse_time=self._cursor_pulse_time,
        )

    def take_action(self) -> ScreenAction | None:
        self._assert_open()
        return self._transition.take_action()

    def _assert_open(self) -> None:
        assert self._is_open, f"{self.__class__.__name__} must be opened before use"

    def _draw_contents(self) -> None:
        self._draw_title_text()

    def _draw_title_text(self) -> None:
        x = 32
        y = 140
        rl.draw_text(self._title, x, y, 28, rl.Color(235, 235, 235, 255))
        y += 34
        for line in self._body_lines:
            rl.draw_text(line, x, y, 18, rl.Color(190, 190, 200, 255))
            y += 22

    def _begin_close_transition(self, action: ScreenAction) -> None:
        if self._transition.closing:
            return
        if isinstance(action, StartRun):
            self.state.screen_fade_alpha = 0.0
            self.state.screen_fade_ramp = True
        if self.state.audio is not None:
            play_sfx(self.state.audio, SfxId.UI_BUTTONCLICK)
        self._transition.begin(action)

    def _init_ground(self) -> None:
        if self.state.pause_background is not None:
            self._ground = None
            return
        self._ground = ensure_menu_ground(self.state)

    def _draw_panel(self) -> None:
        panel = require_runtime_resources(self.state).texture(TextureId.UI_MENU_PANEL)
        _angle_rad, slide_x = ui_element_anim(
            self._transition.timeline_ms,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=MENU_PANEL_WIDTH * self._menu_item_scale(0)[0],
        )
        item_scale, _local_y_shift = self._menu_item_scale(0)
        panel_w = MENU_PANEL_WIDTH * item_scale
        panel_h = float(self._panel_height) * item_scale
        panel_top_left = (
            Vec2(
                self._panel_pos.x + slide_x,
                self._panel_pos.y + self._widescreen_y_shift,
            )
            + self._panel_offset * item_scale
        )
        dst = rl.Rectangle(panel_top_left.x, panel_top_left.y, float(panel_w), float(panel_h))
        shadows_enabled = self.state.config.display.shadows_enabled
        draw_classic_menu_panel(panel, dst=dst, tint=rl.WHITE, shadow=shadows_enabled)

    def _draw_entry(self, entry: MenuEntry) -> None:
        resources = require_runtime_resources(self.state)
        item = resources.texture(TextureId.UI_MENU_ITEM)
        label_tex = resources.texture(TextureId.UI_ITEM_TEXTS)
        item_w = float(item.width)
        item_h = float(item.height)
        _angle_rad, slide_x = ui_element_anim(
            self._transition.timeline_ms,
            index=2,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=item_w * self._menu_item_scale(entry.slot)[0],
        )
        pos = Vec2(self._back_pos.x + slide_x, entry.y + self._widescreen_y_shift)
        item_scale, local_y_shift = self._menu_item_scale(entry.slot)
        offset_x = MENU_ITEM_OFFSET_X * item_scale
        offset_y = MENU_ITEM_OFFSET_Y * item_scale - local_y_shift
        dst = rl.Rectangle(
            pos.x,
            pos.y,
            item_w * item_scale,
            item_h * item_scale,
        )
        origin = rl.Vector2(-offset_x, -offset_y)
        shadows_enabled = self.state.config.display.shadows_enabled
        if shadows_enabled:
            draw_ui_quad_shadow(
                texture=item,
                src=rl.Rectangle(0.0, 0.0, item_w, item_h),
                dst=rl.Rectangle(dst.x + UI_SHADOW_OFFSET, dst.y + UI_SHADOW_OFFSET, dst.width, dst.height),
                origin=origin,
                rotation_deg=0.0,
            )
        draw_ui_quad(
            texture=item,
            src=rl.Rectangle(0.0, 0.0, item_w, item_h),
            dst=dst,
            origin=origin,
            rotation_deg=0.0,
            tint=rl.WHITE,
        )
        alpha = label_alpha(entry.hover_amount)
        tint = rl.Color(255, 255, 255, alpha)
        src = rl.Rectangle(
            0.0,
            float(entry.row) * MENU_LABEL_ROW_HEIGHT,
            MENU_LABEL_WIDTH,
            MENU_LABEL_ROW_HEIGHT,
        )
        label_offset_x = MENU_LABEL_OFFSET_X * item_scale
        label_offset_y = MENU_LABEL_OFFSET_Y * item_scale - local_y_shift
        label_dst = rl.Rectangle(
            pos.x,
            pos.y,
            MENU_LABEL_WIDTH * item_scale,
            MENU_LABEL_HEIGHT * item_scale,
        )
        label_origin = rl.Vector2(-label_offset_x, -label_offset_y)
        draw_ui_quad(
            texture=label_tex,
            src=src,
            dst=label_dst,
            origin=label_origin,
            rotation_deg=0.0,
            tint=tint,
        )
        if self._entry_enabled(entry):
            rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
            draw_ui_quad(
                texture=label_tex,
                src=src,
                dst=label_dst,
                origin=label_origin,
                rotation_deg=0.0,
                tint=rl.Color(255, 255, 255, alpha),
            )
            rl.end_blend_mode()

    def _entry_enabled(self, entry: MenuEntry) -> bool:
        return self._transition.timeline_ms >= PANEL_TIMELINE_START_MS

    def _hovered_entry(self, entry: MenuEntry) -> bool:
        mouse = rl.get_mouse_position()
        mouse_pos = Vec2.from_xy(mouse)
        return self._menu_item_bounds(entry).contains(mouse_pos)

    def _menu_item_scale(self, slot: int) -> tuple[float, float]:
        if self._menu_screen_width < 641:
            return 0.9, float(slot) * 11.0
        return 1.0, 0.0

    def _menu_item_bounds(self, entry: MenuEntry) -> Rect:
        item = require_runtime_resources(self.state).texture(TextureId.UI_MENU_ITEM)
        item_w = float(item.width)
        item_h = float(item.height)
        item_scale, local_y_shift = self._menu_item_scale(entry.slot)
        offset_min = Vec2(
            MENU_ITEM_OFFSET_X * item_scale,
            MENU_ITEM_OFFSET_Y * item_scale - local_y_shift,
        )
        offset_max = Vec2(
            (MENU_ITEM_OFFSET_X + item_w) * item_scale,
            (MENU_ITEM_OFFSET_Y + item_h) * item_scale - local_y_shift,
        )
        size = offset_max - offset_min
        _angle_rad, slide_x = ui_element_anim(
            self._transition.timeline_ms,
            index=2,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=item_w * item_scale,
        )
        pos = Vec2(self._back_pos.x + slide_x, entry.y + self._widescreen_y_shift)
        top_left = pos + Vec2(
            offset_min.x + size.x * 0.54,
            offset_min.y + size.y * 0.28,
        )
        bottom_right = pos + Vec2(
            offset_max.x - size.x * 0.05,
            offset_max.y - size.y * 0.10,
        )
        return Rect.from_pos_size(top_left, bottom_right - top_left)
