from __future__ import annotations

import msgspec

from crimson.game_states import GameStateId
from crimson.screens.actions import Route, ScreenAction, StartRun
from crimson.ui.menu_chrome import draw_ui_quad
from crimson.ui.menu_layout import (
    MENU_LABEL_ROW_HEIGHT,
    MENU_LABEL_ROW_PLAY_GAME,
)
from grim import canvas
from grim.assets import RuntimeResources, TextureId
from grim.fonts.small import SmallFontData, draw_small_text
from grim.geom import Vec2
from grim.raylib_api import rl

from ...game.types import GameState
from ...game_modes import GameMode
from ...ui.dropdown import UiListWidget, ui_list_widget_draw, ui_list_widget_update
from ...ui.perk_menu import UiButtonState, button_draw, button_update
from ..assets import require_runtime_resources
from .base import PanelMenuView


class _PlayGameModeEntry(msgspec.Struct):
    key: str
    label: str
    tooltip: str
    action: ScreenAction
    game_mode: int | None = None
    show_count: bool = False


class _PlayGameContentLayout(msgspec.Struct, frozen=True):
    base_pos: Vec2
    drop_pos: Vec2


class PlayGameMenuView(PanelMenuView):
    """Play Game mode select panel.

    Layout and gating are based on `play_game_menu_update` (crimsonland.exe).
    """

    _PLAYER_COUNT_LABELS = ("1 player", "2 players", "3 players", "4 players")

    def __init__(self, state: GameState) -> None:
        super().__init__(
            state,
            game_state=GameStateId.PLAY_GAME_MENU,
            panel_element=11,
            back_element=12,
            title="Play Game",
        )
        # Native lists two players; the port plays up to four.
        self.player_count_list = UiListWidget(items=self._PLAYER_COUNT_LABELS)

        # Hover fade timers for tooltips (0..1000ms-ish; original uses ~0.0009 alpha scale).
        self._tooltip_ms: dict[str, int] = {}
        self._mode_buttons: dict[str, UiButtonState] = {}

    def open(self) -> None:
        super().open()
        self.player_count_list.open = False
        self._dirty = False
        self._tooltip_ms.clear()
        self._mode_buttons.clear()

    def update(self, dt: float) -> None:
        if not self._update_panel(dt, play_open_sfx=False):
            return
        self._update_back_button()
        entry = self._entry
        if self.state.ui.closing or entry is None or not self._entry_enabled():
            return
        dt_ms = int(min(dt, 0.1) * 1000.0)

        layout = self._content_layout()
        base_pos = layout.base_pos
        resources = require_runtime_resources(self.state)

        mouse = canvas.mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        # An open player-count list disables the mode buttons.
        button_enabled = not self.player_count_list.open

        # `play_game_menu_update` updates the mode buttons top to bottom, then the player-count list.
        y = base_pos.y
        entries, y_step, y_start, _y_end = self._mode_entries()
        y += y_start
        activated: _PlayGameModeEntry | None = None
        for mode in entries:
            clicked, hovered = self._update_mode_button(
                mode,
                Vec2(base_pos.x, y),
                resources=resources,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
                enabled=button_enabled,
            )
            self._update_tooltip_timer(mode.key, hovered, dt_ms)
            if clicked and activated is None:
                activated = mode
            y += y_step

        # Decay timers for modes that aren't visible right now.
        visible = {m.key for m in entries}
        for key in list(self._tooltip_ms):
            if key in visible:
                continue
            self._tooltip_ms[key] = max(0, self._tooltip_ms[key] - dt_ms * 2)

        if self._update_player_count(layout.drop_pos, resources=resources) or activated is None:
            return
        self._activate_mode(activated)

    def _content_layout(self) -> _PlayGameContentLayout:
        panel_top_left = self._panel_rect(self._panel_element).top_left

        # `play_game_menu_update`:
        #   xy = panel_offset_x + panel_x + 330 - 64  (+ animated X offset)
        #   var_1c = panel_offset_y + panel_y + 50
        base_pos = panel_top_left + Vec2(266.0, 50.0)
        drop_pos = base_pos + Vec2(80.0, 1.0)

        return _PlayGameContentLayout(
            base_pos=base_pos,
            drop_pos=drop_pos,
        )

    def _quests_total_played(self) -> int:
        counts = self.state.status.quest_play_counts
        if not counts:
            return 0
        # `play_game_menu_update` sums 40 ints from game_status_blob+0x104..0x1a4.
        # Our `quest_play_counts` array starts at blob+0xd8, so this is indices 11..50.
        return int(sum(int(v) for v in counts[11:51]))

    def _mode_entries(self) -> tuple[list[_PlayGameModeEntry], float, float, float]:
        config = self.state.config
        status = self.state.status

        # Clamp to a valid range; older configs in the repo can contain 0 here,
        # which would incorrectly hide the Tutorial entry (it is gated on == 1).
        player_count = config.gameplay.player_count
        if player_count < 1:
            player_count = 1
        if player_count > len(self._PLAYER_COUNT_LABELS):
            player_count = len(self._PLAYER_COUNT_LABELS)
        quest_unlock = int(status.quest_unlock_index)

        quests_total = self._quests_total_played()
        rush_total = int(status.mode_play_count_for_mode(GameMode.RUSH))
        survival_total = int(status.mode_play_count_for_mode(GameMode.SURVIVAL))
        # Matches the tutorial placement gating in `play_game_menu_update` (excludes Typ-o).
        main_total = quests_total + rush_total + survival_total

        # `play_game_menu_update` uses tighter spacing when quest_unlock>=40 and player_count==1.
        tight_spacing = not (quest_unlock < 0x28 or player_count > 1)
        y_step = 28.0 if tight_spacing else 32.0
        y_start = 26.0 if tight_spacing else 32.0

        has_typo = tight_spacing and player_count == 1
        show_tutorial = player_count == 1

        entries: list[_PlayGameModeEntry] = []
        if show_tutorial and main_total <= 0:
            entries.append(
                _PlayGameModeEntry(
                    key="tutorial",
                    label="Tutorial",
                    tooltip="Learn how to play Crimsonland.",
                    action=StartRun(GameMode.TUTORIAL),
                    game_mode=GameMode.TUTORIAL,
                ),
            )

        entries.extend(
            [
                _PlayGameModeEntry(
                    key="quests",
                    label=" Quests ",
                    tooltip="Unlock new weapons and perks in Quest mode.",
                    action=Route.QUESTS,
                    show_count=True,
                ),
                _PlayGameModeEntry(
                    key="rush",
                    label="  Rush  ",
                    tooltip="Face a rush of aliens in Rush mode.",
                    action=StartRun(GameMode.RUSH),
                    game_mode=GameMode.RUSH,
                    show_count=True,
                ),
                _PlayGameModeEntry(
                    key="survival",
                    label="Survival",
                    tooltip="Gain perks and weapons and fight back.",
                    action=StartRun(GameMode.SURVIVAL),
                    game_mode=GameMode.SURVIVAL,
                    show_count=True,
                ),
            ],
        )

        if has_typo:
            entries.append(
                _PlayGameModeEntry(
                    key="typo",
                    label="Typ'o'Shooter",
                    tooltip="Use your typing skills as the weapon to lay\nthem down.",
                    action=StartRun(GameMode.TYPO),
                    game_mode=GameMode.TYPO,
                    show_count=True,
                ),
            )

        if show_tutorial and main_total > 0:
            entries.append(
                _PlayGameModeEntry(
                    key="tutorial",
                    label="Tutorial",
                    tooltip="Learn how to play Crimsonland.",
                    action=StartRun(GameMode.TUTORIAL),
                    game_mode=GameMode.TUTORIAL,
                ),
            )

        # The y after the last row is used as a tooltip anchor in `play_game_menu_update`.
        y_end = y_start + y_step * float(len(entries))
        return entries, y_step, y_start, y_end

    def _mode_button_state(self, mode: _PlayGameModeEntry) -> UiButtonState:
        state = self._mode_buttons.get(mode.key)
        if state is None:
            state = UiButtonState(mode.label)
            self._mode_buttons[mode.key] = state
        else:
            state.label = mode.label
        return state

    def _update_mode_button(
        self,
        mode: _PlayGameModeEntry,
        pos: Vec2,
        *,
        resources: RuntimeResources,
        dt_ms: int,
        mouse: rl.Vector2,
        click: bool,
        enabled: bool,
    ) -> tuple[bool, bool]:
        state = self._mode_button_state(mode)
        state.enabled = bool(enabled)
        clicked = button_update(
            resources,
            state,
            focus=self.state.focus,
            pos=pos,
            dt_ms=float(dt_ms),
            mouse=mouse,
            click=bool(click),
        )
        return clicked, state.hovered

    def _activate_mode(self, mode: _PlayGameModeEntry) -> None:
        if mode.game_mode is not None:
            self.state.config.gameplay.mode = GameMode(int(mode.game_mode))
            self._dirty = True
        # `play_game_menu_update` fades to black for the modes that start a run.
        self._begin_close_transition(mode.action, fade_to_black=isinstance(mode.action, StartRun))

    def _update_tooltip_timer(self, key: str, hovered: bool, dt_ms: int) -> None:
        value = int(self._tooltip_ms.get(key, 0))
        if hovered:
            value += dt_ms * 6
        else:
            value -= dt_ms * 2
        self._tooltip_ms[key] = max(0, min(1000, value))

    def _update_player_count(self, pos: Vec2, *, resources: RuntimeResources) -> bool:
        """`play_game_menu_update`'s player-count list; returns whether it took the press."""
        widget = self.player_count_list
        widget.selected_index = self.state.config.gameplay.player_count - 1
        focus = self.state.focus
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        selected = ui_list_widget_update(
            resources,
            widget,
            pos,
            focus=focus,
            mouse=Vec2.from_xy(canvas.mouse_position()),
            click=click,
            preserve_bugs=self.state.preserve_bugs,
        )
        # `input_primary_just_pressed() || grim_was_key_pressed(Enter)`.
        pressed = click or focus.enter
        if selected <= -2 or not pressed:
            return False
        widget.open = not widget.open
        if selected >= 0:
            self.state.config.gameplay.player_count = selected + 1
            self._dirty = True
        return True

    def _draw_contents(self) -> None:
        resources = require_runtime_resources(self.state)
        font = resources.small_font
        labels_tex = resources.texture(TextureId.UI_ITEM_TEXTS)
        layout = self._content_layout()
        base_pos = layout.base_pos
        text_color = rl.Color(255, 255, 255, int(255 * 0.8))

        # `play_game_menu_update`: title label at (xy - 64, var_1c - 8), size 128x32.
        title_w = 128.0
        title_h = MENU_LABEL_ROW_HEIGHT
        title_pos = base_pos + Vec2(-64.0, -8.0)

        src = rl.Rectangle(
            0.0,
            float(MENU_LABEL_ROW_PLAY_GAME) * MENU_LABEL_ROW_HEIGHT,
            title_w,
            title_h,
        )
        dst = rl.Rectangle(
            title_pos.x,
            title_pos.y,
            title_w,
            title_h,
        )
        draw_ui_quad(
            texture=labels_tex,
            src=src,
            dst=dst,
            origin=rl.Vector2(0.0, 0.0),
            rotation_deg=0.0,
            tint=rl.WHITE,
        )

        entries, y_step, y_start, y_end = self._mode_entries()
        y = base_pos.y + y_start
        # Native shows the times-played counts while F1 is held.
        show_counts = rl.is_key_down(rl.KeyboardKey.KEY_F1)

        if show_counts:
            draw_small_text(font, "times played:", base_pos + Vec2(132.0, 16.0), text_color)

        for mode in entries:
            self._draw_mode_button(mode, Vec2(base_pos.x, y), resources=resources)
            if show_counts and mode.show_count:
                self._draw_mode_count(
                    mode.key,
                    Vec2(base_pos.x + 158.0, y + 8.0),
                    text_color,
                    font=font,
                )
            y += y_step

        # `play_game_menu_update`: the list widget is drawn before tooltips, so tooltips can overlay it.
        self._draw_player_count(layout.drop_pos, resources=resources)
        self._draw_tooltips(entries, base_pos, y_end, font=font)

    def _draw_player_count(self, pos: Vec2, *, resources: RuntimeResources) -> None:
        widget = self.player_count_list
        widget.selected_index = self.state.config.gameplay.player_count - 1
        ui_list_widget_draw(resources, widget, pos, focus=self.state.focus, mouse=Vec2.from_xy(canvas.mouse_position()))

    def _draw_mode_button(
        self,
        mode: _PlayGameModeEntry,
        pos: Vec2,
        *,
        resources: RuntimeResources,
    ) -> None:
        state = self._mode_button_state(mode)
        button_draw(resources, state, focus=self.state.focus, pos=pos)

    def _draw_mode_count(self, key: str, pos: Vec2, color: rl.Color, *, font: SmallFontData) -> None:
        status = self.state.status
        if key == "quests":
            count = self._quests_total_played()
        elif key == "rush":
            count = int(status.mode_play_count_for_mode(GameMode.RUSH))
        elif key == "survival":
            count = int(status.mode_play_count_for_mode(GameMode.SURVIVAL))
        elif key == "typo":
            count = int(status.mode_play_count_for_mode(GameMode.TYPO))
        else:
            return
        draw_small_text(font, f"{count}", pos, color)

    def _draw_tooltips(
        self,
        entries: list[_PlayGameModeEntry],
        base_pos: Vec2,
        y_end: float,
        *,
        font: SmallFontData,
    ) -> None:
        # `play_game_menu_update` draws these below the mode list based on per-button hover timers.
        tooltip_x = base_pos.x - 55.0
        tooltip_y = base_pos.y + (y_end + 16.0)

        offsets = {
            "quests": (-8.0, 0.0),
            "rush": (32.0, 0.0),
            "survival": (20.0, 0.0),
            "typo": (0.0, -12.0),
            "tutorial": (38.0, 0.0),
        }

        for mode in entries:
            ms = int(self._tooltip_ms.get(mode.key, 0))
            if ms <= 0:
                continue
            alpha_f = min(1.0, float(ms) * 0.0009)
            alpha = int(255 * alpha_f)
            off_x, off_y = offsets.get(mode.key, (0.0, 0.0))
            x = tooltip_x + off_x
            y = tooltip_y + off_y
            for line in mode.tooltip.splitlines():
                draw_small_text(font, line, Vec2(x, y), rl.Color(255, 255, 255, alpha))
                y += font.cell_size
