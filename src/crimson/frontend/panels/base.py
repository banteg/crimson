from __future__ import annotations

from typing import TYPE_CHECKING

import pyray as rl

from grim.assets import PaqTextureCache
from grim.audio import update_audio
from grim.terrain_render import GroundRenderer

from ..assets import MenuAssets, _ensure_texture_cache, load_menu_assets
from ..menu import (
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
    MENU_SCALE_SMALL_THRESHOLD,
    MENU_SIGN_HEIGHT,
    MENU_SIGN_OFFSET_X,
    MENU_SIGN_OFFSET_Y,
    MENU_SIGN_POS_X_PAD,
    MENU_SIGN_POS_Y,
    MENU_SIGN_POS_Y_SMALL,
    MENU_SIGN_WIDTH,
    UI_SHADOW_OFFSET,
    UI_SHADOW_TINT,
    MenuEntry,
    MenuView,
    _draw_menu_cursor,
    ensure_menu_ground,
)
from ..transitions import _draw_screen_fade

if TYPE_CHECKING:
    from ...game import GameState


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
        panel_pos_x: float = PANEL_POS_X,
        panel_pos_y: float = PANEL_POS_Y,
        back_pos_x: float = PANEL_BACK_POS_X,
        back_pos_y: float = PANEL_BACK_POS_Y,
        back_action: str = "back_to_menu",
    ) -> None:
        self._state = state
        self._title = title
        self._body_lines = (body or "").splitlines()
        self._panel_pos_x = panel_pos_x
        self._panel_pos_y = panel_pos_y
        self._back_pos_x = back_pos_x
        self._back_pos_y = back_pos_y
        self._back_action = back_action
        self._assets: MenuAssets | None = None
        self._ground: GroundRenderer | None = None
        self._entry: MenuEntry | None = None
        self._hovered = False
        self._menu_screen_width = 0
        self._widescreen_y_shift = 0.0
        self._timeline_ms = 0
        self._timeline_max_ms = 0
        self._cursor_pulse_time = 0.0
        self._closing = False
        self._close_action: str | None = None
        self._pending_action: str | None = None

    def open(self) -> None:
        layout_w = float(self._state.config.screen_width)
        self._menu_screen_width = int(layout_w)
        self._widescreen_y_shift = MenuView._menu_widescreen_y_shift(layout_w)
        self._assets = load_menu_assets(self._state)
        self._entry = MenuEntry(slot=0, row=MENU_LABEL_ROW_BACK, y=self._back_pos_y)
        self._hovered = False
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._cursor_pulse_time = 0.0
        self._closing = False
        self._close_action = None
        self._pending_action = None
        self._init_ground()

    def close(self) -> None:
        self._ground = None

    def update(self, dt: float) -> None:
        if self._state.audio is not None:
            update_audio(self._state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        self._cursor_pulse_time += min(dt, 0.1) * 1.1
        dt_ms = int(min(dt, 0.1) * 1000.0)
        if self._closing:
            if dt_ms > 0 and self._pending_action is None:
                self._timeline_ms -= dt_ms
                if self._timeline_ms < 0 and self._close_action is not None:
                    self._pending_action = self._close_action
                    self._close_action = None
            return

        if dt_ms > 0:
            self._timeline_ms = min(self._timeline_max_ms, self._timeline_ms + dt_ms)
            if self._timeline_ms >= self._timeline_max_ms:
                self._state.menu_sign_locked = True

        entry = self._entry
        if entry is None:
            return

        enabled = self._entry_enabled(entry)
        hovered = enabled and self._hovered_entry(entry)
        self._hovered = hovered

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) and enabled:
            self._begin_close_transition(self._back_action)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER) and enabled:
            self._begin_close_transition(self._back_action)
        if enabled and hovered and rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT):
            self._begin_close_transition(self._back_action)

        if hovered:
            entry.hover_amount += dt_ms * 6
        else:
            entry.hover_amount -= dt_ms * 2
        entry.hover_amount = max(0, min(1000, entry.hover_amount))

        if entry.ready_timer_ms < 0x100:
            entry.ready_timer_ms = min(0x100, entry.ready_timer_ms + dt_ms)

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        if self._ground is not None:
            self._ground.draw(0.0, 0.0)
        _draw_screen_fade(self._state)
        assets = self._assets
        entry = self._entry
        if assets is None or entry is None:
            return
        self._draw_panel()
        self._draw_entry(entry)
        self._draw_sign()
        self._draw_title_text()
        _draw_menu_cursor(self._state, pulse_time=self._cursor_pulse_time)

    def take_action(self) -> str | None:
        action = self._pending_action
        self._pending_action = None
        return action

    def _draw_title_text(self) -> None:
        x = 32
        y = 140
        rl.draw_text(self._title, x, y, 28, rl.Color(235, 235, 235, 255))
        y += 34
        for line in self._body_lines:
            rl.draw_text(line, x, y, 18, rl.Color(190, 190, 200, 255))
            y += 22

    def _begin_close_transition(self, action: str) -> None:
        if self._closing:
            return
        self._closing = True
        self._close_action = action

    def _ensure_cache(self) -> PaqTextureCache:
        return _ensure_texture_cache(self._state)

    def _init_ground(self) -> None:
        self._ground = ensure_menu_ground(self._state)

    def _draw_panel(self) -> None:
        assets = self._assets
        if assets is None or assets.panel is None:
            return
        panel = assets.panel
        panel_w = MENU_PANEL_WIDTH
        panel_h = MENU_PANEL_HEIGHT
        _angle_rad, slide_x = MenuView._ui_element_anim(
            self,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w * self._menu_item_scale(0)[0],
        )
        item_scale, _local_y_shift = self._menu_item_scale(0)
        dst = rl.Rectangle(
            self._panel_pos_x + slide_x,
            self._panel_pos_y + self._widescreen_y_shift,
            panel_w * item_scale,
            panel_h * item_scale,
        )
        origin = rl.Vector2(-(MENU_PANEL_OFFSET_X * item_scale), -(MENU_PANEL_OFFSET_Y * item_scale))
        fx_detail = bool(self._state.config.data.get("fx_detail_0", 0))
        if fx_detail:
            MenuView._draw_ui_quad_shadow(
                texture=panel,
                src=rl.Rectangle(0.0, 0.0, float(panel.width), float(panel.height)),
                dst=rl.Rectangle(dst.x + UI_SHADOW_OFFSET, dst.y + UI_SHADOW_OFFSET, dst.width, dst.height),
                origin=origin,
                rotation_deg=0.0,
            )
        MenuView._draw_ui_quad(
            texture=panel,
            src=rl.Rectangle(0.0, 0.0, float(panel.width), float(panel.height)),
            dst=dst,
            origin=origin,
            rotation_deg=0.0,
            tint=rl.WHITE,
        )

    def _draw_entry(self, entry: MenuEntry) -> None:
        assets = self._assets
        if assets is None or assets.labels is None:
            return
        item = assets.item
        if item is None:
            return
        label_tex = assets.labels
        item_w = float(item.width)
        item_h = float(item.height)
        pos_x = self._back_pos_x
        pos_y = entry.y + self._widescreen_y_shift
        _angle_rad, slide_x = MenuView._ui_element_anim(
            self,
            index=2,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=item_w * self._menu_item_scale(entry.slot)[0],
        )
        pos_x += slide_x
        item_scale, local_y_shift = self._menu_item_scale(entry.slot)
        offset_x = MENU_ITEM_OFFSET_X * item_scale
        offset_y = MENU_ITEM_OFFSET_Y * item_scale - local_y_shift
        dst = rl.Rectangle(
            pos_x,
            pos_y,
            item_w * item_scale,
            item_h * item_scale,
        )
        origin = rl.Vector2(-offset_x, -offset_y)
        fx_detail = bool(self._state.config.data.get("fx_detail_0", 0))
        if fx_detail:
            MenuView._draw_ui_quad_shadow(
                texture=item,
                src=rl.Rectangle(0.0, 0.0, item_w, item_h),
                dst=rl.Rectangle(dst.x + UI_SHADOW_OFFSET, dst.y + UI_SHADOW_OFFSET, dst.width, dst.height),
                origin=origin,
                rotation_deg=0.0,
            )
        MenuView._draw_ui_quad(
            texture=item,
            src=rl.Rectangle(0.0, 0.0, item_w, item_h),
            dst=dst,
            origin=origin,
            rotation_deg=0.0,
            tint=rl.WHITE,
        )
        alpha = MenuView._label_alpha(entry.hover_amount)
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
            pos_x,
            pos_y,
            MENU_LABEL_WIDTH * item_scale,
            MENU_LABEL_HEIGHT * item_scale,
        )
        label_origin = rl.Vector2(-label_offset_x, -label_offset_y)
        MenuView._draw_ui_quad(
            texture=label_tex,
            src=src,
            dst=label_dst,
            origin=label_origin,
            rotation_deg=0.0,
            tint=tint,
        )
        if self._entry_enabled(entry):
            rl.begin_blend_mode(rl.BLEND_ADDITIVE)
            MenuView._draw_ui_quad(
                texture=label_tex,
                src=src,
                dst=label_dst,
                origin=label_origin,
                rotation_deg=0.0,
                tint=rl.Color(255, 255, 255, alpha),
            )
            rl.end_blend_mode()

    def _draw_sign(self) -> None:
        assets = self._assets
        if assets is None or assets.sign is None:
            return
        screen_w = float(self._state.config.screen_width)
        scale, shift_x = MenuView._sign_layout_scale(int(screen_w))
        pos_x = screen_w + MENU_SIGN_POS_X_PAD
        pos_y = MENU_SIGN_POS_Y if screen_w > MENU_SCALE_SMALL_THRESHOLD else MENU_SIGN_POS_Y_SMALL
        sign_w = MENU_SIGN_WIDTH * scale
        sign_h = MENU_SIGN_HEIGHT * scale
        offset_x = MENU_SIGN_OFFSET_X * scale + shift_x
        offset_y = MENU_SIGN_OFFSET_Y * scale
        # Quest screen is only reachable after the Play Game panel is fully visible,
        # so the sign is already locked in place. Keep it static here.
        rotation_deg = 0.0
        sign = assets.sign
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

    def _entry_enabled(self, entry: MenuEntry) -> bool:
        return self._timeline_ms >= PANEL_TIMELINE_START_MS

    def _hovered_entry(self, entry: MenuEntry) -> bool:
        left, top, right, bottom = self._menu_item_bounds(entry)
        mouse = rl.get_mouse_position()
        mouse_x = float(mouse.x)
        mouse_y = float(mouse.y)
        return left <= mouse_x <= right and top <= mouse_y <= bottom

    def _menu_item_scale(self, slot: int) -> tuple[float, float]:
        if self._menu_screen_width < 641:
            return 0.9, float(slot) * 11.0
        return 1.0, 0.0

    def _menu_item_bounds(self, entry: MenuEntry) -> tuple[float, float, float, float]:
        assets = self._assets
        if assets is None or assets.item is None:
            return (0.0, 0.0, 0.0, 0.0)
        item_w = float(assets.item.width)
        item_h = float(assets.item.height)
        item_scale, local_y_shift = self._menu_item_scale(entry.slot)
        x0 = MENU_ITEM_OFFSET_X * item_scale
        y0 = MENU_ITEM_OFFSET_Y * item_scale - local_y_shift
        x2 = (MENU_ITEM_OFFSET_X + item_w) * item_scale
        y2 = (MENU_ITEM_OFFSET_Y + item_h) * item_scale - local_y_shift
        w = x2 - x0
        h = y2 - y0
        _angle_rad, slide_x = MenuView._ui_element_anim(
            self,
            index=2,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=item_w * item_scale,
        )
        pos_x = self._back_pos_x + slide_x
        pos_y = entry.y + self._widescreen_y_shift
        left = pos_x + x0 + w * 0.54
        top = pos_y + y0 + h * 0.28
        right = pos_x + x2 - w * 0.05
        bottom = pos_y + y2 - h * 0.10
        return left, top, right, bottom
