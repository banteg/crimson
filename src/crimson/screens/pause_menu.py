from __future__ import annotations

import math

from crimson.screens.actions import Route, ScreenAction
from crimson.screens.chrome import draw_screen_background, draw_screen_cursor
from crimson.screens.transitions import ScreenTransition
from crimson.ui.animation import ui_element_anim
from crimson.ui.layout import menu_widescreen_y_shift
from crimson.ui.menu_chrome import draw_menu_sign, draw_ui_quad
from crimson.ui.menu_layout import (
    MENU_ITEM_OFFSET_X,
    MENU_ITEM_OFFSET_Y,
    MENU_LABEL_BASE_Y,
    MENU_LABEL_HEIGHT,
    MENU_LABEL_OFFSET_X,
    MENU_LABEL_OFFSET_Y,
    MENU_LABEL_ROW_BACK,
    MENU_LABEL_ROW_HEIGHT,
    MENU_LABEL_ROW_OPTIONS,
    MENU_LABEL_ROW_QUIT,
    MENU_LABEL_STEP,
    MENU_LABEL_WIDTH,
    MENU_SCALE_SMALL_THRESHOLD,
    MenuEntry,
    label_alpha,
    menu_slot_end_ms,
    menu_slot_pos_x,
    menu_slot_start_ms,
)
from crimson.ui.shadow import UI_SHADOW_OFFSET, draw_ui_quad_shadow
from grim.assets import TextureId
from grim.audio import play_sfx, update_audio
from grim.geom import Rect, Vec2
from grim.raylib_api import rl
from grim.sfx_map import SfxId

from ..game.types import GameState
from .assets import require_runtime_resources
from .transitions import _draw_screen_fade

PAUSE_MENU_TO_MAIN_MENU_FADE_MS = 500


class PauseMenuView:
    def __init__(self, state: GameState) -> None:
        self.state = state
        self._is_open = False
        self._menu_entries: list[MenuEntry] = []
        self._selected_index = 0
        self._focus_timer_ms = 0
        self._hovered_index: int | None = None
        self._transition = ScreenTransition()
        self._transition.duration_ms = 0
        self._cursor_pulse_time = 0.0
        self._widescreen_y_shift = 0.0
        self._menu_screen_width = 0
        self._panel_open_sfx_played = False

    def open(self) -> None:
        layout_w = float(self.state.config.display.width)
        self._menu_screen_width = int(layout_w)
        self._widescreen_y_shift = menu_widescreen_y_shift(layout_w)
        ys = [
            MENU_LABEL_BASE_Y + self._widescreen_y_shift,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP + self._widescreen_y_shift,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP * 2.0 + self._widescreen_y_shift,
        ]
        self._menu_entries = [
            MenuEntry(slot=0, row=MENU_LABEL_ROW_OPTIONS, y=ys[0]),
            MenuEntry(slot=1, row=MENU_LABEL_ROW_QUIT, y=ys[1]),
            MenuEntry(slot=2, row=MENU_LABEL_ROW_BACK, y=ys[2]),
        ]
        self._selected_index = 0 if self._menu_entries else -1
        self._focus_timer_ms = 0
        self._hovered_index = None
        self._transition.reset()
        self._transition.duration_ms = max(300, *(menu_slot_start_ms(entry.slot) for entry in self._menu_entries))
        self._cursor_pulse_time = 0.0
        self._panel_open_sfx_played = False
        self._is_open = True

    def resume(self) -> None:
        self._transition.reset()
        self._hovered_index = None
        self._panel_open_sfx_played = False

    def close(self) -> None:
        self._is_open = False
        self._menu_entries = []

    def update(self, dt: float) -> None:
        self._assert_open()
        if self.state.audio is not None:
            update_audio(self.state.audio, dt)
        self._cursor_pulse_time += min(dt, 0.1) * 1.1

        dt_ms = int(min(dt, 0.1) * 1000.0)
        if not self._transition.advance(dt_ms):
            self._focus_timer_ms = max(0, self._focus_timer_ms - dt_ms)
            return

        if dt_ms > 0:
            self._focus_timer_ms = max(0, self._focus_timer_ms - dt_ms)
            if self._transition.timeline_ms >= self._transition.duration_ms:
                self.state.menu_sign_locked = True
                if (not self._panel_open_sfx_played) and (self.state.audio is not None):
                    play_sfx(self.state.audio, SfxId.UI_PANELCLICK)
                    self._panel_open_sfx_played = True

        if not self._menu_entries:
            return

        self._hovered_index = self._hovered_entry_index()

        if rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            reverse = rl.is_key_down(rl.KeyboardKey.KEY_LEFT_SHIFT) or rl.is_key_down(rl.KeyboardKey.KEY_RIGHT_SHIFT)
            delta = -1 if reverse else 1
            self._selected_index = (self._selected_index + delta) % len(self._menu_entries)
            self._focus_timer_ms = 1000

        activated_index: int | None = None
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            # ESC behaves like selecting Back.
            activated_index = self._entry_index_for_row(MENU_LABEL_ROW_BACK)
        elif rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER) and 0 <= self._selected_index < len(self._menu_entries):
            entry = self._menu_entries[self._selected_index]
            if self._menu_entry_enabled(entry):
                activated_index = self._selected_index

        if (
            activated_index is None
            and self._hovered_index is not None
            and rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        ):
            hovered = self._hovered_index
            entry = self._menu_entries[hovered]
            if self._menu_entry_enabled(entry):
                self._selected_index = hovered
                self._focus_timer_ms = 1000
                activated_index = hovered

        if activated_index is not None:
            self._activate_menu_entry(activated_index)

        self._update_ready_timers(dt_ms)
        self._update_hover_amounts(dt_ms)

    def draw(self) -> None:
        self._assert_open()
        draw_screen_background(self.state, None, entity_alpha=self._pause_background_entity_alpha())
        _draw_screen_fade(self.state)

        self._draw_menu_items()
        draw_menu_sign(
            require_runtime_resources(self.state),
            width=self.state.config.display.width,
            shadows=self.state.config.display.shadows_enabled,
            locked=self.state.menu_sign_locked,
            timeline_ms=self._transition.timeline_ms,
        )
        draw_screen_cursor(
            resources=require_runtime_resources(self.state),
            pulse_time=self._cursor_pulse_time,
        )

    def take_action(self) -> ScreenAction | None:
        self._assert_open()
        return self._transition.take_action()

    def _assert_open(self) -> None:
        assert self._is_open, "PauseMenuView must be opened before use"

    def _pause_background_entity_alpha(self) -> float:
        # Native gameplay_render_world keeps gameplay entities fully visible for most transitions,
        # but fades them out when pause menu closes to main menu (ui_element_slot_28 timing = 0x1f4 ms).
        if (not self._transition.closing) or (self._transition.action != Route.MENU):
            return 1.0
        alpha = float(self._transition.timeline_ms) / float(PAUSE_MENU_TO_MAIN_MENU_FADE_MS)
        if alpha < 0.0:
            return 0.0
        if alpha > 1.0:
            return 1.0
        return alpha

    def _activate_menu_entry(self, index: int) -> None:
        if not (0 <= index < len(self._menu_entries)):
            return
        entry = self._menu_entries[index]
        action = self._action_for_entry(entry)
        if action is None:
            return
        if self.state.audio is not None:
            play_sfx(self.state.audio, SfxId.UI_BUTTONCLICK)
        self._begin_close_transition(action)

    @staticmethod
    def _action_for_entry(entry: MenuEntry) -> ScreenAction | None:
        if entry.row == MENU_LABEL_ROW_OPTIONS:
            return Route.OPTIONS
        if entry.row == MENU_LABEL_ROW_QUIT:
            return Route.MENU
        if entry.row == MENU_LABEL_ROW_BACK:
            return Route.BACK
        return None

    def _begin_close_transition(self, action: ScreenAction) -> None:
        if self._transition.closing:
            return
        self._transition.begin(action)

    def _menu_item_scale(self, slot: int) -> tuple[float, float]:
        if self._menu_screen_width < (MENU_SCALE_SMALL_THRESHOLD + 1):
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
        pos = Vec2(menu_slot_pos_x(entry.slot), entry.y)
        top_left = pos + Vec2(offset_min.x + size.x * 0.54, offset_min.y + size.y * 0.28)
        bottom_right = pos + Vec2(offset_max.x - size.x * 0.05, offset_max.y - size.y * 0.10)
        return Rect.from_pos_size(top_left, bottom_right - top_left)

    def _hovered_entry_index(self) -> int | None:
        if not self._menu_entries:
            return None
        mouse = rl.get_mouse_position()
        mouse_pos = Vec2.from_xy(mouse)
        for idx, entry in enumerate(self._menu_entries):
            if not self._menu_entry_enabled(entry):
                continue
            if self._menu_item_bounds(entry).contains(mouse_pos):
                return idx
        return None

    def _update_ready_timers(self, dt_ms: int) -> None:
        for entry in self._menu_entries:
            if entry.ready_timer_ms < 0x100:
                entry.ready_timer_ms = min(0x100, entry.ready_timer_ms + dt_ms)

    def _update_hover_amounts(self, dt_ms: int) -> None:
        hovered_index = self._hovered_index
        for idx, entry in enumerate(self._menu_entries):
            hover = hovered_index is not None and idx == hovered_index
            if hover:
                entry.hover_amount += dt_ms * 6
            else:
                entry.hover_amount -= dt_ms * 2
            entry.hover_amount = max(0, min(1000, entry.hover_amount))

    def _menu_entry_enabled(self, entry: MenuEntry) -> bool:
        return self._transition.timeline_ms >= menu_slot_start_ms(entry.slot)

    def _draw_menu_items(self) -> None:
        if not self._menu_entries:
            return
        resources = require_runtime_resources(self.state)
        item = resources.texture(TextureId.UI_MENU_ITEM)
        label_tex = resources.texture(TextureId.UI_ITEM_TEXTS)
        item_w = float(item.width)
        item_h = float(item.height)
        shadows_enabled = self.state.config.display.shadows_enabled
        for idx in range(len(self._menu_entries) - 1, -1, -1):
            entry = self._menu_entries[idx]
            pos = Vec2(menu_slot_pos_x(entry.slot), entry.y)
            angle_rad, slide_x = ui_element_anim(
                self._transition.timeline_ms,
                index=entry.slot + 2,
                start_ms=menu_slot_start_ms(entry.slot),
                end_ms=menu_slot_end_ms(entry.slot),
                width=item_w,
            )
            _ = slide_x  # slide is ignored for render_mode==0 (transform) elements
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
            rotation_deg = math.degrees(angle_rad)
            if shadows_enabled:
                draw_ui_quad_shadow(
                    texture=item,
                    src=rl.Rectangle(0.0, 0.0, item_w, item_h),
                    dst=rl.Rectangle(dst.x + UI_SHADOW_OFFSET, dst.y + UI_SHADOW_OFFSET, dst.width, dst.height),
                    origin=origin,
                    rotation_deg=rotation_deg,
                )
            draw_ui_quad(
                texture=item,
                src=rl.Rectangle(0.0, 0.0, item_w, item_h),
                dst=dst,
                origin=origin,
                rotation_deg=rotation_deg,
                tint=rl.WHITE,
            )
            counter_value = entry.hover_amount
            if idx == self._selected_index and self._focus_timer_ms > 0:
                counter_value = self._focus_timer_ms
            alpha = label_alpha(counter_value)
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
                rotation_deg=rotation_deg,
                tint=tint,
            )
            if self._menu_entry_enabled(entry):
                glow_alpha = alpha
                if 0 <= entry.ready_timer_ms < 0x100:
                    glow_alpha = 0xFF - (entry.ready_timer_ms // 2)
                rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
                draw_ui_quad(
                    texture=label_tex,
                    src=src,
                    dst=label_dst,
                    origin=label_origin,
                    rotation_deg=rotation_deg,
                    tint=rl.Color(255, 255, 255, glow_alpha),
                )
                rl.end_blend_mode()

    def _entry_index_for_row(self, row: int) -> int | None:
        for idx, entry in enumerate(self._menu_entries):
            if entry.row == row:
                return idx
        return None
