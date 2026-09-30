from __future__ import annotations

from crimson.game_states import GameStateId
from crimson.input_codes import PadCode, pad_nav_pressed
from crimson.screens.actions import Route, ScreenAction
from crimson.ui.animation import ui_transition_alpha
from crimson.ui.cursor import ui_cursor_render
from crimson.ui.layout import menu_widescreen_y_shift
from crimson.ui.menu_chrome import draw_menu_entry, draw_menu_sign
from crimson.ui.menu_layout import (
    MENU_LABEL_BASE_Y,
    MENU_LABEL_ROW_BACK,
    MENU_LABEL_ROW_OPTIONS,
    MENU_LABEL_ROW_QUIT,
    MENU_LABEL_STEP,
    MenuEntry,
    menu_entry_activated,
    menu_entry_update,
    menu_slot_pos_x,
    pause_menu_item_scale,
)
from grim import canvas
from grim.assets import TextureId
from grim.geom import Vec2
from grim.raylib_api import rl

from ..game.types import GameState
from .assets import require_runtime_resources
from .menu_screen import MenuScreen


class PauseMenuView(MenuScreen):
    game_state = GameStateId.PAUSE_MENU

    def __init__(self, state: GameState) -> None:
        super().__init__(state)
        self._menu_entries: list[MenuEntry] = []
        self._widescreen_y_shift = 0.0
        self._menu_screen_width = 0

    def open(self) -> None:
        layout_w = float(self.state.config.display.width)
        self._menu_screen_width = int(layout_w)
        self._widescreen_y_shift = menu_widescreen_y_shift(layout_w)
        entries: list[MenuEntry] = []
        for slot, row in enumerate((MENU_LABEL_ROW_OPTIONS, MENU_LABEL_ROW_QUIT, MENU_LABEL_ROW_BACK)):
            scale, rise = pause_menu_item_scale(self._menu_screen_width, slot)
            pos = Vec2(menu_slot_pos_x(slot), MENU_LABEL_BASE_Y + MENU_LABEL_STEP * slot + self._widescreen_y_shift)
            entries.append(MenuEntry(element=slot + 23, row=row, pos=pos, scale=scale, rise=rise))
        self._menu_entries = entries
        super().open()

    def close(self) -> None:
        super().close()
        self._menu_entries = []

    def update(self, dt: float) -> None:
        live = self._advance(dt)
        if live:
            self._lock_sign(dt)
        if not self._menu_entries:
            return

        # `ui_element_update` / `ui_element_render`, registered top to bottom like the main menu (native walks the
        # table backwards), and run on while the items slide out.
        item = require_runtime_resources(self.state).texture(TextureId.UI_MENU_ITEM)
        item_size = Vec2(float(item.width), float(item.height))
        mouse = Vec2.from_xy(canvas.mouse_position())
        dt_ms = int(min(dt, 0.1) * 1000.0)
        focus = self.state.focus
        for entry in self._menu_entries:
            menu_entry_update(entry, item_size=item_size, mouse=mouse, dt_ms=dt_ms, focus=focus, live=live)
        if not live:
            return
        if focus.escape or pad_nav_pressed(PadCode.START):
            # ESC behaves like selecting Back.
            self._begin_close_transition(Route.BACK)
            return
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        for entry in self._menu_entries:
            if menu_entry_activated(entry, timeline_ms=self.state.ui.timeline_ms, focus=focus, click=click):
                self._begin_close_transition(self._action_for_entry(entry))
                return

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

    @staticmethod
    def _action_for_entry(entry: MenuEntry) -> ScreenAction:
        if entry.row == MENU_LABEL_ROW_OPTIONS:
            return Route.OPTIONS
        if entry.row == MENU_LABEL_ROW_QUIT:
            return Route.MENU
        return Route.BACK

    def _draw_menu_items(self) -> None:
        resources = require_runtime_resources(self.state)
        for entry in reversed(self._menu_entries):
            draw_menu_entry(
                resources,
                entry,
                timeline_ms=self.state.ui.timeline_ms,
                shadows=self.state.config.display.shadows_enabled,
            )
