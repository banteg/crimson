from __future__ import annotations

from grim.audio import play_sfx, update_audio
from grim.sfx_map import SfxId
from grim.terrain_render import GroundRenderer

from ..game.types import GameState
from ..game_states import GameStateId
from ..ui.animation import game_state_elements, ui_element_timeline_window
from .actions import ScreenAction
from .chrome import draw_screen_background, ensure_menu_ground
from .transitions import _draw_screen_fade


class MenuScreen:
    """One native menu state on the shared timeline.

    `game_state_set` enters it (`open`, or `resume` when a screen above it closes), `ui_elements_update_and_render`
    runs its timeline, and a button makes the next state pending (`_begin_close_transition`), which the stack takes
    once the timeline has run back out.
    """

    game_state: GameStateId

    def __init__(self, state: GameState) -> None:
        self.state = state
        self._is_open = False
        self._ground: GroundRenderer | None = None
        # A setting changed on this screen, saved as it closes.
        self._dirty = False
        # The `ui_element_table` entries `game_state_set` turned on for this screen.
        self._elements: tuple[int, ...] = ()

    def open(self) -> None:
        # A run retained underneath draws the world instead of the menu ground.
        self._ground = None if self.state.pause_background is not None else ensure_menu_ground(self.state)
        self._enter()
        self._is_open = True

    def resume(self) -> None:
        self._enter()

    def _enter(self) -> None:
        self._elements = self._ui_elements()
        # `ui_elements_max_timeline`: the latest `timeline_end_ms` among them.
        self.state.ui.enter(max((ui_element_timeline_window(index)[1] for index in self._elements), default=0))

    def _ui_elements(self) -> tuple[int, ...]:
        return game_state_elements(self.game_state)

    def close(self) -> None:
        self._is_open = False
        self._ground = None

    def take_action(self) -> ScreenAction | None:
        self._assert_open()
        return self.state.ui.take_action()

    def _assert_open(self) -> None:
        assert self._is_open, f"{type(self).__name__} must be opened before use"

    def _begin_close_transition(self, action: ScreenAction, *, fade_to_black: bool = False) -> None:
        """The button click: `ui_transition_direction = 0; game_state_pending = ...`, and `screen_fade_ramp_flag`
        for the buttons that start a run."""
        if self.state.ui.closing:
            return
        if self._dirty:
            try:
                self.state.config.save()
            except (OSError, ValueError) as exc:
                self.state.console.log.log(f"config: save failed: {exc}")
            else:
                self._dirty = False
        if fade_to_black:
            self.state.screen_fade_alpha = 0.0
            self.state.screen_fade_ramp = True
        if self.state.audio is not None:
            play_sfx(self.state.audio, SfxId.UI_BUTTONCLICK)
        self.state.ui.begin(action)

    def _advance(self, dt: float) -> bool:
        """The frame's audio and ground, then the timeline; False while it runs out.

        `ui_element_update` clicks as each of the screen's elements comes in, on the frame the timeline reaches its
        `timeline_end_ms` (one click a frame: `sfx_play` holds a sound for 50ms); the sign clicks only while it is
        not locked.
        """
        self._assert_open()
        if self.state.audio is not None:
            update_audio(self.state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        before_ms = self.state.ui.timeline_ms
        live = self.state.ui.advance(int(min(dt, 0.1) * 1000.0))
        if live and self.state.audio is not None:
            for index in self._elements:
                if index == 0 and self.state.menu_sign_locked:
                    continue
                if before_ms < ui_element_timeline_window(index)[1] <= self.state.ui.timeline_ms:
                    play_sfx(self.state.audio, SfxId.UI_PANELCLICK)
        return live

    def _lock_sign(self, dt: float) -> None:
        """`ui_elements_update_and_render` locks the sign once the timeline is in."""
        if int(min(dt, 0.1) * 1000.0) <= 0 or not self.state.ui.opened:
            return
        self.state.menu_sign_locked = True

    def _draw_background(self, *, entity_alpha: float = 1.0) -> None:
        draw_screen_background(self.state, self._ground, entity_alpha=entity_alpha)
        _draw_screen_fade(self.state)
