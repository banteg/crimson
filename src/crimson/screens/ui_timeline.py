from __future__ import annotations

import msgspec

from .actions import ScreenAction


class UiTimeline(msgspec.Struct):
    """The one menu timeline: native `ui_elements_timeline`, `ui_transition_direction` and `game_state_pending`.

    Entering a screen (`game_state_set`) rewinds it to 0 and runs it forward to the screen's
    `ui_elements_max_timeline`; leaving runs it back down, and the pending action fires once it drops below 0.
    """

    timeline_ms: int = 0
    max_timeline_ms: int = 0
    closing: bool = False
    pending: ScreenAction | None = None
    ready: bool = False

    def enter(self, max_timeline_ms: int) -> None:
        self.timeline_ms = 0
        self.max_timeline_ms = max_timeline_ms
        self.closing = False
        self.pending = None
        self.ready = False

    def begin(self, action: ScreenAction | None = None) -> None:
        if not self.closing:
            self.closing = True
            self.pending = action

    def advance(self, dt_ms: int) -> bool:
        """`ui_elements_update_and_render`: move the timeline; False while closing."""
        if self.closing:
            if dt_ms > 0 and not self.ready:
                self.timeline_ms -= dt_ms
                self.ready = self.timeline_ms < 0
            return False
        if dt_ms > 0:
            self.timeline_ms = min(self.max_timeline_ms, self.timeline_ms + dt_ms)
        return True

    @property
    def opened(self) -> bool:
        return self.timeline_ms >= self.max_timeline_ms

    def take_action(self) -> ScreenAction | None:
        if not self.ready:
            return None
        action = self.pending
        self.pending = None
        return action
