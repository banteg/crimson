from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import random

import pyray as rl

from .entrypoint import DEFAULT_BASE_DIR
from .raylib_app import run_view
from .views.types import View


@dataclass(frozen=True, slots=True)
class GameConfig:
    base_dir: Path = DEFAULT_BASE_DIR
    width: int = 1024
    height: int = 768
    fps: int = 60
    seed: int | None = None


@dataclass(frozen=True, slots=True)
class GameState:
    base_dir: Path
    rng: random.Random


class BootView:
    def __init__(self, state: GameState) -> None:
        self._state = state

    def update(self, dt: float) -> None:
        del dt

    def draw(self) -> None:
        rl.clear_background(rl.Color(8, 8, 10, 255))
        rl.draw_text(
            "Boot step 1: RNG seeded + window init",
            24,
            24,
            20,
            rl.Color(220, 220, 220, 255),
        )


def run_game(config: GameConfig) -> None:
    base_dir = config.base_dir
    base_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(config.seed)
    state = GameState(base_dir=base_dir, rng=rng)
    view: View = BootView(state)
    run_view(
        view,
        width=config.width,
        height=config.height,
        title="Crimsonland",
        fps=config.fps,
    )
