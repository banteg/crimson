from __future__ import annotations

import os

from crimson.game_states import GameStateId
from crimson.screens.actions import Route
from crimson.ui.animation import game_state_elements
from crimson.ui.cursor import ui_cursor_render
from crimson.ui.layout import menu_widescreen_y_shift
from crimson.ui.menu_chrome import draw_menu_entry, draw_menu_sign
from crimson.ui.menu_layout import (
    MENU_LABEL_BASE_Y,
    MENU_LABEL_ROW_OPTIONS,
    MENU_LABEL_ROW_OTHER_GAMES,
    MENU_LABEL_ROW_PLAY_GAME,
    MENU_LABEL_ROW_QUIT,
    MENU_LABEL_ROW_STATISTICS,
    MENU_LABEL_STEP,
    MenuEntry,
    main_menu_item_scale,
    menu_entry_activated,
    menu_entry_update,
    menu_slot_pos_x,
)
from grim import canvas
from grim.assets import RuntimeResources, TextureId
from grim.geom import Vec2
from grim.music import play_music, stop_music
from grim.raylib_api import rl

from ..game.types import GameState
from .assets import require_runtime_resources
from .menu_screen import MenuScreen


class MenuView(MenuScreen):
    game_state = GameStateId.MAIN_MENU

    def __init__(self, state: GameState) -> None:
        super().__init__(state)
        self._menu_entries: list[MenuEntry] = []
        self._widescreen_y_shift = 0.0
        self._menu_screen_width = 0

    def open(self) -> None:
        layout_w = float(self.state.config.display.width)
        self._menu_screen_width = int(layout_w)
        self._widescreen_y_shift = menu_widescreen_y_shift(layout_w)
        self._menu_entries = self._menu_entries_for_flags(other_games=self._other_games_enabled())
        super().open()
        if self.state.audio is not None:
            if self.state.audio.music.active_track != "crimson_theme":
                stop_music(self.state.audio.music)
            play_music(self.state.audio.music, "crimson_theme")

    def _ui_elements(self) -> tuple[int, ...]:
        return game_state_elements(GameStateId.MAIN_MENU, other_games=self._other_games_enabled())

    def update(self, dt: float) -> None:
        if self.state.audio is not None and not self.state.ui.closing:
            play_music(self.state.audio.music, "crimson_theme")
        live = self._advance(dt)
        if live:
            self._lock_sign(dt)
        if not self._menu_entries:
            return

        # `ui_elements_update_and_render` runs `ui_element_update` and `ui_element_render` on while the items slide
        # out, so the clicked item keeps lighting up. Each item with a click handler registers for focus, and Enter on
        # the focused one activates it. Native walks the element table backwards, which puts Quit first (Enter on a
        # fresh menu quits) and walks Tab up the menu; the port registers the items top to bottom.
        item = require_runtime_resources(self.state).texture(TextureId.UI_MENU_ITEM)
        item_size = Vec2(float(item.width), float(item.height))
        mouse = Vec2.from_xy(canvas.mouse_position())
        dt_ms = int(min(dt, 0.1) * 1000.0)
        focus = self.state.focus
        for entry in self._menu_entries:
            menu_entry_update(entry, item_size=item_size, mouse=mouse, dt_ms=dt_ms, focus=focus, live=live)
        if not live:
            return
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        for entry in self._menu_entries:
            if menu_entry_activated(entry, timeline_ms=self.state.ui.timeline_ms, focus=focus, click=click):
                self._activate_menu_entry(entry)
                return

    def draw(self) -> None:
        self._assert_open()
        self._draw_background()
        resources = require_runtime_resources(self.state)
        self._draw_menu_items(resources)
        draw_menu_sign(
            resources,
            width=self.state.config.display.width,
            shadows=self.state.config.display.shadows_enabled,
            locked=self.state.menu_sign_locked,
            timeline_ms=self.state.ui.timeline_ms,
        )
        ui_cursor_render(resources, dt=self.state.frame_dt)

    def _activate_menu_entry(self, entry: MenuEntry) -> None:
        self.state.console.log.log(f"menu select: {entry.element} (row {entry.row})")
        self.state.console.log.flush()
        if entry.row == MENU_LABEL_ROW_QUIT:
            self._begin_quit_transition()
        elif entry.row == MENU_LABEL_ROW_PLAY_GAME:
            self._begin_close_transition(Route.PLAY_GAME)
        elif entry.row == MENU_LABEL_ROW_OPTIONS:
            self._begin_close_transition(Route.OPTIONS)
        elif entry.row == MENU_LABEL_ROW_STATISTICS:
            self._begin_close_transition(Route.STATISTICS)
        elif entry.row == MENU_LABEL_ROW_OTHER_GAMES:
            self._begin_close_transition(Route.OTHER_GAMES)

    def _begin_quit_transition(self) -> None:
        self.state.menu_sign_locked = False
        self._begin_close_transition(Route.QUIT)

    def _menu_entries_for_flags(self, other_games: bool) -> list[MenuEntry]:
        rows = self._menu_label_rows(other_games)
        slot_ys = self._menu_slot_ys(other_games, self._widescreen_y_shift)
        active = self._menu_slot_active(other_games)
        entries: list[MenuEntry] = []
        for slot, (row, y, enabled) in enumerate(zip(rows, slot_ys, active, strict=False)):
            if not enabled:
                continue
            scale, rise = main_menu_item_scale(self._menu_screen_width, slot)
            entries.append(
                MenuEntry(element=slot + 2, row=row, pos=Vec2(menu_slot_pos_x(slot), y), scale=scale, rise=rise),
            )
        return entries

    @staticmethod
    def _menu_label_rows(other_games: bool) -> list[int]:
        # Label atlas rows in ui_itemTexts.jaz:
        #   0 BUY NOW (shareware only), 1 PLAY GAME, 2 OPTIONS, 3 STATISTICS, 4 MODS,
        #   5 OTHER GAMES, 6 QUIT, 7 BACK
        top = 4
        if other_games:
            return [top, 1, 2, 3, 5, 6]
        # ui_menu_layout_init swaps table idx 6/7 depending on config var 100:
        # when empty, QUIT becomes idx 6 and the idx 7 element is inactive.
        return [top, 1, 2, 3, 6, 7]

    @staticmethod
    def _menu_slot_ys(_other_games: bool, y_shift: float) -> list[float]:
        ys = [
            MENU_LABEL_BASE_Y,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP * 2.0,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP * 3.0,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP * 4.0,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP * 5.0,
        ]
        return [y + y_shift for y in ys]

    @staticmethod
    def _menu_slot_active(other_games: bool) -> list[bool]:
        # The top slot is the full version's Mods, which no version runs.
        if other_games:
            return [False, True, True, True, True, True]
        return [False, True, True, True, True, False]

    def _draw_menu_items(self, resources: RuntimeResources) -> None:
        # `ui_elements_update_and_render` walks the table backwards: later items draw first, earlier ones on top.
        for entry in reversed(self._menu_entries):
            draw_menu_entry(
                resources,
                entry,
                timeline_ms=self.state.ui.timeline_ms,
                shadows=self.state.config.display.shadows_enabled,
            )

    def _other_games_enabled(self) -> bool:
        # Original game checks a config string via grim_get_config_var(100).
        # Our config-var system is not implemented yet; allow a simple env opt-in.
        return os.getenv("CRIMSON_GRIM_CONFIG_VAR_100", "").strip() != ""
