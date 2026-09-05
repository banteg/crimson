from __future__ import annotations

import msgspec

from grim.raylib_api import rl

from ..game.types import GameState
from .actions import ScreenAction


class ScreenTransition(msgspec.Struct):
    """Panel/menu timeline with one close request, emitted after sliding offscreen."""

    duration_ms: int = 300
    timeline_ms: int = 0
    closing: bool = False
    action: ScreenAction | None = None
    ready: bool = False

    def reset(self) -> None:
        self.timeline_ms = 0
        self.closing = False
        self.action = None
        self.ready = False

    def begin(self, action: ScreenAction) -> None:
        if not self.closing:
            self.closing = True
            self.action = action

    def advance(self, dt_ms: int) -> bool:
        if self.closing:
            if dt_ms > 0 and not self.ready:
                self.timeline_ms -= dt_ms
                self.ready = self.timeline_ms < 0
            return False
        if dt_ms > 0:
            self.timeline_ms = min(self.duration_ms, self.timeline_ms + dt_ms)
        return True

    def take_action(self) -> ScreenAction | None:
        if not self.ready:
            return None
        action = self.action
        self.action = None
        return action


SCREEN_FADE_OUT_RATE = 2.0
SCREEN_FADE_IN_RATE = 10.0


def _update_screen_fade(state: GameState, dt: float) -> None:
    if state.screen_fade_ramp:
        state.screen_fade_alpha += float(dt) * SCREEN_FADE_IN_RATE
    else:
        state.screen_fade_alpha -= float(dt) * SCREEN_FADE_OUT_RATE
    if state.screen_fade_alpha < 0.0:
        state.screen_fade_alpha = 0.0
    elif state.screen_fade_alpha > 1.0:
        state.screen_fade_alpha = 1.0


def _draw_screen_fade(state: GameState) -> None:
    alpha = float(state.screen_fade_alpha)
    if alpha <= 0.0:
        return
    shade = int(max(0.0, min(1.0, alpha)) * 255.0)
    rl.draw_rectangle(0, 0, int(rl.get_screen_width()), int(rl.get_screen_height()), rl.Color(0, 0, 0, shade))
