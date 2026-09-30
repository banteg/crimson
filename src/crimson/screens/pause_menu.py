from __future__ import annotations

import math

from crimson.game_states import GameStateId
from crimson.input_codes import PadCode, pad_nav_pressed
from crimson.screens.actions import Route, ScreenAction
from crimson.ui.animation import (
    ui_element_anim,
    ui_element_timeline_window,
    ui_transition_alpha,
)
from crimson.ui.cursor import ui_cursor_render
from crimson.ui.layout import menu_widescreen_y_shift
from crimson.ui.menu_chrome import draw_menu_item, draw_menu_sign
from crimson.ui.menu_layout import (
    MENU_LABEL_BASE_Y,
    MENU_LABEL_ROW_BACK,
    MENU_LABEL_ROW_OPTIONS,
    MENU_LABEL_ROW_QUIT,
    MENU_LABEL_STEP,
    MenuEntry,
    label_alpha,
    menu_item_bounds,
    menu_slot_pos_x,
    pause_menu_item_scale,
    update_menu_item_timers,
)
from grim import canvas
from grim.assets import TextureId
from grim.geom import Rect, Vec2
from grim.raylib_api import rl

from ..game.types import GameState
from .assets import require_runtime_resources
from .menu_screen import MenuScreen


class PauseMenuView(MenuScreen):
    game_state = GameStateId.PAUSE_MENU

    def __init__(self, state: GameState) -> None:
        super().__init__(state)
        self._menu_entries: list[MenuEntry] = []
        self._hovered_index: int | None = None
        self._widescreen_y_shift = 0.0
        self._menu_screen_width = 0

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
        super().open()

    def _enter(self) -> None:
        super()._enter()
        self._hovered_index = None

    def close(self) -> None:
        super().close()
        self._menu_entries = []

    def update(self, dt: float) -> None:
        dt_ms = int(min(dt, 0.1) * 1000.0)
        if not self._advance(dt):
            # `ui_element_update` runs on while the items slide out, so the clicked item keeps lighting up.
            update_menu_item_timers(
                self._menu_entries, self._hovered_index, dt_ms, focus_timer_ms=self.state.focus.timer_ms,
            )
            return

        self._lock_sign(dt)

        if not self._menu_entries:
            return

        self._hovered_index = self._hovered_entry_index()

        # `ui_element_render` focus, registered top to bottom like the main menu (native walks the table backwards).
        focus = self.state.focus
        activated_index: int | None = None
        for index, entry in enumerate(self._menu_entries):
            entry.focused = focus.update(entry)
            if entry.focused and focus.enter and self._menu_entry_enabled(entry):
                activated_index = index
        if focus.escape or pad_nav_pressed(PadCode.START):
            # ESC behaves like selecting Back.
            activated_index = self._entry_index_for_row(MENU_LABEL_ROW_BACK)

        if (
            activated_index is None
            and self._hovered_index is not None
            and rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        ):
            hovered = self._hovered_index
            entry = self._menu_entries[hovered]
            if self._menu_entry_enabled(entry):
                activated_index = hovered

        if activated_index is not None:
            self._activate_menu_entry(activated_index)

        update_menu_item_timers(self._menu_entries, self._hovered_index, dt_ms, focus_timer_ms=focus.timer_ms)

    def draw(self) -> None:
        self._assert_open()
        self._draw_background(entity_alpha=self._pause_background_entity_alpha())

        self._draw_menu_items()
        draw_menu_sign(
            require_runtime_resources(self.state),
            width=self.state.config.display.width,
            shadows=self.state.config.display.shadows_enabled,
            locked=self.state.menu_sign_locked,
            timeline_ms=self.state.ui.timeline_ms,
        )
        ui_cursor_render(require_runtime_resources(self.state), dt=self.state.frame_dt)

    def _pause_background_entity_alpha(self) -> float:
        # The pause items set `game_state_pending`; only quitting to the main menu fades the run out.
        match self.state.ui.pending:
            case None:
                pending = None
            case Route.MENU:
                pending = GameStateId.MAIN_MENU
            case Route.OPTIONS:
                pending = GameStateId.OPTIONS_MENU
            case _:
                pending = GameStateId.GAMEPLAY
        return ui_transition_alpha(self.state.ui.timeline_ms, state=GameStateId.PAUSE_MENU, pending=pending)

    def _activate_menu_entry(self, index: int) -> None:
        if not (0 <= index < len(self._menu_entries)):
            return
        entry = self._menu_entries[index]
        action = self._action_for_entry(entry)
        if action is None:
            return
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

    def _menu_item_bounds(self, entry: MenuEntry) -> Rect:
        item = require_runtime_resources(self.state).texture(TextureId.UI_MENU_ITEM)
        item_scale, local_y_shift = pause_menu_item_scale(self._menu_screen_width, entry.slot)
        return menu_item_bounds(
            Vec2(menu_slot_pos_x(entry.slot), entry.y),
            Vec2(float(item.width), float(item.height)),
            item_scale,
            local_y_shift,
        )

    def _hovered_entry_index(self) -> int | None:
        if not self._menu_entries:
            return None
        mouse = canvas.mouse_position()
        mouse_pos = Vec2.from_xy(mouse)
        for idx, entry in enumerate(self._menu_entries):
            if not self._menu_entry_enabled(entry):
                continue
            if self._menu_item_bounds(entry).contains(mouse_pos):
                return idx
        return None

    def _menu_entry_enabled(self, entry: MenuEntry) -> bool:
        return self.state.ui.timeline_ms >= ui_element_timeline_window(entry.slot + 23)[1]

    def _draw_menu_items(self) -> None:
        if not self._menu_entries:
            return
        resources = require_runtime_resources(self.state)
        item_w = float(resources.texture(TextureId.UI_MENU_ITEM).width)
        shadows_enabled = self.state.config.display.shadows_enabled
        for idx in range(len(self._menu_entries) - 1, -1, -1):
            entry = self._menu_entries[idx]
            pos = Vec2(menu_slot_pos_x(entry.slot), entry.y)
            angle_rad, slide_x = ui_element_anim(
                self.state.ui.timeline_ms,
                index=entry.slot + 23,
                width=item_w,
            )
            _ = slide_x  # slide is ignored for render_mode==0 (transform) elements
            item_scale, local_y_shift = pause_menu_item_scale(self._menu_screen_width, entry.slot)
            alpha = label_alpha(entry.hover_amount)
            glow_alpha = None
            if self._menu_entry_enabled(entry):
                glow_alpha = alpha
                if 0 <= entry.ready_timer_ms < 0x100:
                    glow_alpha = 0xFF - (entry.ready_timer_ms // 2)
            draw_menu_item(
                resources,
                pos=pos,
                row=entry.row,
                item_scale=item_scale,
                local_y_shift=local_y_shift,
                rotation_deg=math.degrees(angle_rad),
                alpha=alpha,
                glow_alpha=glow_alpha,
                shadows=shadows_enabled,
            )

    def _entry_index_for_row(self, row: int) -> int | None:
        for idx, entry in enumerate(self._menu_entries):
            if entry.row == row:
                return idx
        return None
