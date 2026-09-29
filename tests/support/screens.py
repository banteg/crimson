from __future__ import annotations

from crimson.game.loop_view import GameLoopView
from crimson.game.navigation import ScreenNavigator
from crimson.game.types import GameState, Screen
from crimson.modes.base_gameplay_mode import BaseGameplayMode
from crimson.screens.actions import ScreenAction, StartRun


class ScreenStub:
    def __init__(self) -> None:
        self.open_calls = 0
        self.close_calls = 0
        self.resume_calls = 0
        self.action: ScreenAction | None = None

    def open(self) -> None:
        self.open_calls += 1

    def close(self) -> None:
        self.close_calls += 1

    def resume(self) -> None:
        self.resume_calls += 1

    def update(self, dt: float) -> None:
        pass

    def draw(self) -> None:
        pass

    def take_action(self) -> ScreenAction | None:
        action, self.action = self.action, None
        return action


def update_frame(screen: Screen, state: GameState, dt: float = 0.016) -> None:
    """One game-loop frame of `screen`: the loop starts the focus frame (sampling the keys), then updates it."""
    state.focus.begin_frame(int(min(dt, 0.1) * 1000.0))
    screen.update(dt)


def finish_transition(loop: GameLoopView) -> None:
    """Run the loop long enough for any menu transition to finish."""
    for _ in range(12):
        loop.update(0.1)


def start_run(state: GameState, request: StartRun) -> tuple[ScreenNavigator, BaseGameplayMode]:
    """Start `request` as the game does; screens navigated to next retain the run as their background."""
    navigator = ScreenNavigator(state)
    navigator.navigate(request)
    run = state.screens.gameplay
    assert isinstance(run, BaseGameplayMode)
    return navigator, run
