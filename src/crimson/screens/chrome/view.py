from __future__ import annotations

from grim.geom import Vec2

from ...game.types import GameState, ScreenAction
from ..assets import require_runtime_resources
from .geometry import MENU_PANEL_OFFSET_X, MENU_PANEL_OFFSET_Y, single_panel_frame
from .runtime import ChromeRuntime, ChromeSpec, ChromeState, ChromeTick

PANEL_TIMELINE_START_MS = 300
PANEL_TIMELINE_END_MS = 0


class ChromeScreenView:
    def __init__(self, state: GameState, *, chrome_spec: ChromeSpec) -> None:
        self.state = state
        self._chrome = ChromeRuntime(state, spec=chrome_spec)

    @property
    def _chrome_state(self) -> ChromeState:
        return self._chrome.chrome

    def open(self) -> None:
        self._chrome.open()
        self._reset_view_state()

    def close(self) -> None:
        self._chrome.close()
        self._reset_closed_state()

    def take_action(self) -> ScreenAction | None:
        return self._chrome.take_action()

    def resume_from_child(self) -> None:
        self._restart_open_timeline(play_open_sfx=True)

    def _assert_open(self) -> None:
        assert self._chrome.is_open, f"{self.__class__.__name__} must be opened before use"

    def _update_chrome(self, dt: float) -> ChromeTick:
        return self._chrome.update(dt)

    def _begin_close_transition(self, action: ScreenAction) -> None:
        self._chrome.begin_close_transition(action, before_close=self._before_close_transition)

    def _before_close_transition(self, action: ScreenAction) -> None:
        del action

    def _draw_background(self, *, entity_alpha: float | None = None) -> None:
        self._chrome.draw_background(entity_alpha=entity_alpha)

    def _draw_fade(self) -> None:
        self._chrome.draw_fade()

    def _draw_sign(self, *, animated: bool = False) -> None:
        self._chrome.draw_sign(resources=require_runtime_resources(self.state), animated=animated)

    def _draw_cursor(self) -> None:
        self._chrome.draw_cursor(resources=require_runtime_resources(self.state))

    def _panel_frame(
        self,
        *,
        panel_pos: Vec2,
        panel_height: float,
        panel_offset: Vec2 = Vec2(MENU_PANEL_OFFSET_X, MENU_PANEL_OFFSET_Y),
        small_scale: float = 0.9,
        start_ms: int = PANEL_TIMELINE_START_MS,
        end_ms: int = PANEL_TIMELINE_END_MS,
    ):
        chrome = self._chrome_state
        return single_panel_frame(
            chrome.timeline_ms,
            screen_width=float(chrome.screen_width),
            widescreen_y_shift=chrome.widescreen_y_shift,
            panel_pos=panel_pos,
            panel_offset=panel_offset,
            panel_height=panel_height,
            start_ms=start_ms,
            end_ms=end_ms,
            small_scale=small_scale,
        )

    def _restart_open_timeline(self, *, play_open_sfx: bool = False) -> None:
        self._chrome.restart_open_timeline(play_open_sfx=play_open_sfx)

    def _reset_view_state(self) -> None:
        return

    def _reset_closed_state(self) -> None:
        return
