from __future__ import annotations

import math
import os

from crimson.game_states import GameStateId
from crimson.screens.actions import Route, ScreenAction
from crimson.screens.chrome import ensure_menu_ground, menu_ground_camera
from crimson.ui.animation import ui_element_anim, ui_element_timeline_window, ui_elements_max_timeline
from crimson.ui.cursor import ui_cursor_render
from crimson.ui.layout import menu_widescreen_y_shift
from crimson.ui.menu_chrome import draw_menu_item, draw_menu_sign
from crimson.ui.menu_layout import (
    MENU_LABEL_BASE_Y,
    MENU_LABEL_ROW_MODS,
    MENU_LABEL_ROW_OPTIONS,
    MENU_LABEL_ROW_OTHER_GAMES,
    MENU_LABEL_ROW_PLAY_GAME,
    MENU_LABEL_ROW_QUIT,
    MENU_LABEL_ROW_STATISTICS,
    MENU_LABEL_STEP,
    MenuEntry,
    label_alpha,
    main_menu_item_scale,
    menu_item_bounds,
    menu_slot_pos_x,
    update_menu_item_timers,
)
from grim import canvas
from grim.assets import RuntimeResources, TextureId
from grim.audio import play_music, play_sfx, stop_music, update_audio
from grim.geom import Rect, Vec2
from grim.raylib_api import rl
from grim.sfx_map import SfxId
from grim.terrain_render import GroundRenderer

from ..game.types import GameState
from .assets import require_runtime_resources
from .transitions import _draw_screen_fade


class MenuView:
    def __init__(self, state: GameState) -> None:
        self.state = state
        self._is_open = False
        self._ground: GroundRenderer | None = None
        self._menu_entries: list[MenuEntry] = []
        self._hovered_index: int | None = None
        self._widescreen_y_shift = 0.0
        self._menu_screen_width = 0
        self._panel_open_sfx_played = False

    def open(self) -> None:
        layout_w = float(self.state.config.display.width)
        self._menu_screen_width = int(layout_w)
        self._widescreen_y_shift = menu_widescreen_y_shift(layout_w)
        self._menu_entries = self._menu_entries_for_flags(
            mods_available=self._mods_available(),
            other_games=self._other_games_enabled(),
        )
        self._hovered_index = None
        self._enter_timeline()
        self._panel_open_sfx_played = False
        self._init_ground()
        if self.state.audio is not None:
            if self.state.audio.music.active_track != "crimson_theme":
                stop_music(self.state.audio)
            play_music(self.state.audio, "crimson_theme")
        self._is_open = True

    def resume(self) -> None:
        self._enter_timeline()
        self._panel_open_sfx_played = False

    def _enter_timeline(self) -> None:
        self.state.ui.enter(
            ui_elements_max_timeline(
                GameStateId.MAIN_MENU, mods_available=self._mods_available(), other_games=self._other_games_enabled(),
            ),
        )

    def close(self) -> None:
        self._is_open = False
        self._ground = None

    def update(self, dt: float) -> None:
        self._assert_open()
        if self.state.audio is not None:
            if not self.state.ui.closing:
                play_music(self.state.audio, "crimson_theme")
            update_audio(self.state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        dt_ms = int(min(dt, 0.1) * 1000.0)
        if not self.state.ui.advance(dt_ms):
            # `ui_element_update` runs on while the items slide out, so the clicked item keeps lighting up.
            update_menu_item_timers(
                self._menu_entries, self._hovered_index, dt_ms, focus_timer_ms=self.state.focus.timer_ms,
            )
            return

        if dt_ms > 0 and self.state.ui.timeline_ms >= self.state.ui.max_timeline_ms:
            self.state.menu_sign_locked = True
            if (not self._panel_open_sfx_played) and (self.state.audio is not None):
                play_sfx(self.state.audio, SfxId.UI_PANELCLICK)
                self._panel_open_sfx_played = True
        if not self._menu_entries:
            return

        resources = require_runtime_resources(self.state)
        self._hovered_index = self._hovered_entry_index(resources)

        # `ui_element_render`: each item with a click handler registers for focus, and Enter on the focused one
        # activates it. Native walks the element table backwards, which puts Quit first (Enter on a fresh menu
        # quits) and walks Tab up the menu; the port registers the items top to bottom.
        focus = self.state.focus
        activated_index: int | None = None
        for index, entry in enumerate(self._menu_entries):
            entry.focused = focus.update(entry)
            if entry.focused and focus.enter and self._menu_entry_enabled(entry):
                activated_index = index

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
        rl.clear_background(rl.BLACK)
        if self._ground is not None:
            self._ground.draw(menu_ground_camera(self.state))
        _draw_screen_fade(self.state)
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

    def take_action(self) -> ScreenAction | None:
        self._assert_open()
        return self.state.ui.take_action()

    def _assert_open(self) -> None:
        assert self._is_open, "MenuView must be opened before use"

    def _activate_menu_entry(self, index: int) -> None:
        if not (0 <= index < len(self._menu_entries)):
            return
        entry = self._menu_entries[index]
        if self.state.audio is not None:
            play_sfx(self.state.audio, SfxId.UI_BUTTONCLICK)
        self.state.console.log.log(f"menu select: {index} (row {entry.row})")
        self.state.console.log.flush()
        if entry.row == MENU_LABEL_ROW_QUIT:
            self._begin_quit_transition()
        elif entry.row == MENU_LABEL_ROW_PLAY_GAME:
            self._begin_close_transition(Route.PLAY_GAME)
        elif entry.row == MENU_LABEL_ROW_OPTIONS:
            self._begin_close_transition(Route.OPTIONS)
        elif entry.row == MENU_LABEL_ROW_STATISTICS:
            self._begin_close_transition(Route.STATISTICS)
        elif entry.row == MENU_LABEL_ROW_MODS:
            self._begin_close_transition(Route.MODS)
        elif entry.row == MENU_LABEL_ROW_OTHER_GAMES:
            self._begin_close_transition(Route.OTHER_GAMES)

    def _begin_close_transition(self, action: ScreenAction) -> None:
        if self.state.ui.closing:
            return
        self.state.ui.begin(action)

    def _begin_quit_transition(self) -> None:
        self.state.menu_sign_locked = False
        self._begin_close_transition(Route.QUIT)

    def _init_ground(self) -> None:
        self._ground = ensure_menu_ground(self.state)

    def _menu_entries_for_flags(
        self,
        mods_available: bool,
        other_games: bool,
    ) -> list[MenuEntry]:
        rows = self._menu_label_rows(other_games)
        slot_ys = self._menu_slot_ys(other_games, self._widescreen_y_shift)
        active = self._menu_slot_active(mods_available, other_games)
        entries: list[MenuEntry] = []
        for slot, (row, y, enabled) in enumerate(zip(rows, slot_ys, active, strict=False)):
            if not enabled:
                continue
            entries.append(MenuEntry(slot=slot, row=row, y=y))
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
    def _menu_slot_active(
        mods_available: bool,
        other_games: bool,
    ) -> list[bool]:
        show_top = mods_available
        if other_games:
            return [show_top, True, True, True, True, True]
        return [show_top, True, True, True, True, False]

    def _draw_menu_items(self, resources: RuntimeResources) -> None:
        if not self._menu_entries:
            return
        item_w = float(resources.texture(TextureId.UI_MENU_ITEM).width)
        shadows_enabled = self.state.config.display.shadows_enabled
        # Matches ui_elements_update_and_render reverse table iteration:
        # later entries draw first, earlier entries draw last (on top).
        for idx in range(len(self._menu_entries) - 1, -1, -1):
            entry = self._menu_entries[idx]
            pos = Vec2(menu_slot_pos_x(entry.slot), entry.y)
            angle_rad, slide_x = ui_element_anim(
                self.state.ui.timeline_ms,
                index=entry.slot + 2,
                width=item_w,
            )
            _ = slide_x  # slide is ignored for render_mode==0 (transform) elements
            item_scale, local_y_shift = main_menu_item_scale(self._menu_screen_width, entry.slot)
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

    def _mods_available(self) -> bool:
        mods_dir = self.state.base_dir / "mods"
        if not mods_dir.exists():
            return False
        return any(mods_dir.glob("*.dll"))

    def _other_games_enabled(self) -> bool:
        # Original game checks a config string via grim_get_config_var(100).
        # Our config-var system is not implemented yet; allow a simple env opt-in.
        return os.getenv("CRIMSON_GRIM_CONFIG_VAR_100", "").strip() != ""

    def _hovered_entry_index(self, resources: RuntimeResources) -> int | None:
        if not self._menu_entries:
            return None
        mouse = canvas.mouse_position()
        mouse_pos = Vec2.from_xy(mouse)
        for idx, entry in enumerate(self._menu_entries):
            if not self._menu_entry_enabled(entry):
                continue
            if self._menu_item_bounds(entry, resources).contains(mouse_pos):
                return idx
        return None

    def _menu_entry_enabled(self, entry: MenuEntry) -> bool:
        return self.state.ui.timeline_ms >= ui_element_timeline_window(entry.slot + 2)[1]

    def _menu_item_bounds(self, entry: MenuEntry, resources: RuntimeResources) -> Rect:
        item = resources.texture(TextureId.UI_MENU_ITEM)
        item_scale, local_y_shift = main_menu_item_scale(self._menu_screen_width, entry.slot)
        return menu_item_bounds(
            Vec2(menu_slot_pos_x(entry.slot), entry.y),
            Vec2(float(item.width), float(item.height)),
            item_scale,
            local_y_shift,
        )

