from __future__ import annotations

from crimson.game.types import GameState
from crimson.pause_background import PauseBackground
from crimson.screens.actions import ScreenAction
from crimson.screens.stack import ScreenEntry
from tests.support.gameplay_screen import GameplayScreenStub


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


class BackgroundGameplayStub(GameplayScreenStub):
    def __init__(self, background: PauseBackground) -> None:
        super().__init__()
        self.background = background

    def draw_pause_background(self, *, entity_alpha: float = 1.0) -> None:
        self.background.draw_pause_background(entity_alpha=entity_alpha)


def install_background(state: GameState, background: PauseBackground) -> None:
    """Isolate a panel draw test with a real retained-run/background relationship."""
    gameplay = BackgroundGameplayStub(background)
    state.screens.close()
    state.screens.push(ScreenEntry(gameplay, resume=gameplay.resume, gameplay=gameplay))
    overlay = ScreenStub()
    state.screens.push(ScreenEntry(overlay, resume=overlay.resume))
