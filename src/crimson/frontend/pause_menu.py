from __future__ import annotations

import math

import pyray as rl

from grim.audio import play_sfx, update_audio
from grim.geom import Rect, Vec2

from .assets import MenuAssets, load_menu_assets
from .menu import (
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
    MENU_SIGN_HEIGHT,
    MENU_SIGN_OFFSET_X,
    MENU_SIGN_OFFSET_Y,
    MENU_SIGN_POS_X_PAD,
    MENU_SIGN_POS_Y,
    MENU_SIGN_POS_Y_SMALL,
    MENU_SIGN_WIDTH,
    UI_SHADOW_OFFSET,
    MenuEntry,
    MenuView,
    _draw_menu_cursor,
)
from .transitions import _draw_screen_fade

from .types import GameState, PauseBackground


PAUSE_MENU_TO_MAIN_MENU_FADE_MS = 500


class PauseMenuView:
    def __init__(self, state: GameState) -> None:
        self._state = state
        self._assets: MenuAssets | None = None
        self._menu_entries: list[MenuEntry] = []
        self._selected_index = 0
        self._focus_timer_ms = 0
        self._hovered_index: int | None = None
        self._timeline_ms = 0
        self._timeline_max_ms = 0
        self._cursor_pulse_time = 0.0
        self._widescreen_y_shift = 0.0
        self._menu_screen_width = 0
        self._closing = False
        self._close_action: str | None = None
        self._pending_action: str | None = None
        self._panel_open_sfx_played = False

    def open(self) -> None:
        layout_w = float(self._state.config.screen_width)
        self._menu_screen_width = int(layout_w)
        self._widescreen_y_shift = MenuView._menu_widescreen_y_shift(layout_w)
        self._assets = load_menu_assets(self._state)

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
        self._timeline_ms = 0
        self._timeline_max_ms = max(300, *(MenuView._menu_slot_start_ms(entry.slot) for entry in self._menu_entries))
        self._cursor_pulse_time = 0.0
        self._closing = False
        self._close_action = None
        self._pending_action = None
        self._panel_open_sfx_played = False

    def close(self) -> None:
        self._assets = None
        self._menu_entries = []

    def update(self, dt: float) -> None:
        if self._state.audio is not None:
            update_audio(self._state.audio, dt)
        self._cursor_pulse_time += min(dt, 0.1) * 1.1

        dt_ms = int(min(dt, 0.1) * 1000.0)
        if self._closing:
            if dt_ms > 0 and self._pending_action is None:
                self._timeline_ms -= dt_ms
                self._focus_timer_ms = max(0, self._focus_timer_ms - dt_ms)
                if self._timeline_ms < 0 and self._close_action is not None:
                    self._pending_action = self._close_action
                    self._close_action = None
            return

        if dt_ms > 0:
            self._timeline_ms = min(self._timeline_max_ms, self._timeline_ms + dt_ms)
            self._focus_timer_ms = max(0, self._focus_timer_ms - dt_ms)
            if self._timeline_ms >= self._timeline_max_ms:
                self._state.menu_sign_locked = True
                if (not self._panel_open_sfx_played) and (self._state.audio is not None):
                    play_sfx(self._state.audio, "sfx_ui_panelclick", rng=self._state.rng)
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

        if activated_index is None and self._hovered_index is not None:
            if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
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
        rl.clear_background(rl.BLACK)
        pause_background = self._pause_background()
        if pause_background is not None:
            pause_background.draw_pause_background(entity_alpha=self._pause_background_entity_alpha())
        _draw_screen_fade(self._state)

        assets = self._assets
        if assets is None:
            return
        self._draw_menu_items()
        self._draw_menu_sign()
        _draw_menu_cursor(self._state, pulse_time=self._cursor_pulse_time)

    def take_action(self) -> str | None:
        action = self._pending_action
        self._pending_action = None
        return action

    def _pause_background(self) -> PauseBackground | None:
        return self._state.pause_background

    def _pause_background_entity_alpha(self) -> float:
        # Native gameplay_render_world keeps gameplay entities fully visible for most transitions,
        # but fades them out when pause menu closes to main menu (ui_element_slot_28 timing = 0x1f4 ms).
        if (not self._closing) or (self._close_action != "back_to_menu"):
            return 1.0
        alpha = float(self._timeline_ms) / float(PAUSE_MENU_TO_MAIN_MENU_FADE_MS)
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
        if self._state.audio is not None:
            play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
        self._begin_close_transition(action)

    @staticmethod
    def _action_for_entry(entry: MenuEntry) -> str | None:
        if entry.row == MENU_LABEL_ROW_OPTIONS:
            return "open_options"
        if entry.row == MENU_LABEL_ROW_QUIT:
            return "back_to_menu"
        if entry.row == MENU_LABEL_ROW_BACK:
            return "back_to_previous"
        return None

    def _begin_close_transition(self, action: str) -> None:
        if self._closing:
            return
        self._closing = True
        self._close_action = action

    def _menu_item_scale(self, slot: int) -> tuple[float, float]:
        if self._menu_screen_width < (MENU_SCALE_SMALL_THRESHOLD + 1):
            return 0.9, float(slot) * 11.0
        return 1.0, 0.0

    def _ui_element_anim(
        self,
        *,
        index: int,
        start_ms: int,
        end_ms: int,
        width: float,
    ) -> tuple[float, float]:
        # Matches ui_element_update: angle lerps pi/2 -> 0 over [end_ms, start_ms].
        # Direction flag (element+0x314) appears to be 0 for menu elements.
        if start_ms <= end_ms or width <= 0.0:
            return 0.0, 0.0
        t = self._timeline_ms
        if t < end_ms:
            angle = 1.5707964
            offset_x = -abs(width)
        elif t < start_ms:
            elapsed = t - end_ms
            span = float(start_ms - end_ms)
            p = float(elapsed) / span
            angle = 1.5707964 * (1.0 - p)
            offset_x = -((1.0 - p) * abs(width))
        else:
            angle = 0.0
            offset_x = 0.0
        if index == 0:
            angle = -abs(angle)
        return angle, offset_x

    def _menu_item_bounds(self, entry: MenuEntry) -> Rect:
        assets = self._assets
        if assets is None or assets.item is None:
            return Rect()
        item_w = float(assets.item.width)
        item_h = float(assets.item.height)
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
        pos = Vec2(MenuView._menu_slot_pos_x(entry.slot), entry.y)
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
        return self._timeline_ms >= MenuView._menu_slot_start_ms(entry.slot)

    def _draw_menu_items(self) -> None:
        assets = self._assets
        if assets is None or assets.labels is None or not self._menu_entries:
            return
        item = assets.item
        if item is None:
            return
        label_tex = assets.labels
        item_w = float(item.width)
        item_h = float(item.height)
        fx_detail = bool(self._state.config.data.get("fx_detail_0", 0))
        for idx in range(len(self._menu_entries) - 1, -1, -1):
            entry = self._menu_entries[idx]
            pos = Vec2(MenuView._menu_slot_pos_x(entry.slot), entry.y)
            angle_rad, slide_x = self._ui_element_anim(
                index=entry.slot + 2,
                start_ms=MenuView._menu_slot_start_ms(entry.slot),
                end_ms=MenuView._menu_slot_end_ms(entry.slot),
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
            if fx_detail:
                MenuView._draw_ui_quad_shadow(
                    texture=item,
                    src=rl.Rectangle(0.0, 0.0, item_w, item_h),
                    dst=rl.Rectangle(dst.x + UI_SHADOW_OFFSET, dst.y + UI_SHADOW_OFFSET, dst.width, dst.height),
                    origin=origin,
                    rotation_deg=rotation_deg,
                )
            MenuView._draw_ui_quad(
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
            alpha = MenuView._label_alpha(counter_value)
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
            MenuView._draw_ui_quad(
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
                MenuView._draw_ui_quad(
                    texture=label_tex,
                    src=src,
                    dst=label_dst,
                    origin=label_origin,
                    rotation_deg=rotation_deg,
                    tint=rl.Color(255, 255, 255, glow_alpha),
                )
                rl.end_blend_mode()

    def _draw_menu_sign(self) -> None:
        assets = self._assets
        if assets is None or assets.sign is None:
            return
        screen_w = float(self._state.config.screen_width)
        scale, shift_x = MenuView._sign_layout_scale(int(screen_w))
        sign_pos = Vec2(
            screen_w + MENU_SIGN_POS_X_PAD,
            MENU_SIGN_POS_Y if screen_w > MENU_SCALE_SMALL_THRESHOLD else MENU_SIGN_POS_Y_SMALL,
        )
        sign_w = MENU_SIGN_WIDTH * scale
        sign_h = MENU_SIGN_HEIGHT * scale
        offset_x = MENU_SIGN_OFFSET_X * scale + shift_x
        offset_y = MENU_SIGN_OFFSET_Y * scale
        rotation_deg = 0.0
        if not self._state.menu_sign_locked:
            angle_rad, slide_x = self._ui_element_anim(
                index=0,
                start_ms=300,
                end_ms=0,
                width=sign_w,
            )
            _ = slide_x
            rotation_deg = math.degrees(angle_rad)
        sign = assets.sign
        fx_detail = bool(self._state.config.data.get("fx_detail_0", 0))
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

    def _entry_index_for_row(self, row: int) -> int | None:
        for idx, entry in enumerate(self._menu_entries):
            if entry.row == row:
                return idx
        return None
