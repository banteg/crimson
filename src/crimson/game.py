from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import random

import pyray as rl

from .config import CrimsonConfig, ensure_crimson_cfg
from .console import ConsoleState, create_console
from .entrypoint import DEFAULT_BASE_DIR
from .raylib_app import run_view
from .views.types import View


@dataclass(frozen=True, slots=True)
class GameConfig:
    base_dir: Path = DEFAULT_BASE_DIR
    width: int | None = None
    height: int | None = None
    fps: int = 60
    seed: int | None = None


@dataclass(frozen=True, slots=True)
class GameState:
    base_dir: Path
    rng: random.Random
    config: CrimsonConfig
    console: ConsoleState


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
        rl.draw_text(
            f"Config: {self._state.config.screen_width}x{self._state.config.screen_height} "
            f"windowed={self._state.config.windowed_flag}",
            24,
            52,
            18,
            rl.Color(180, 180, 180, 255),
        )


def run_game(config: GameConfig) -> None:
    base_dir = config.base_dir
    base_dir.mkdir(parents=True, exist_ok=True)
    cfg = ensure_crimson_cfg(base_dir)
    width = cfg.screen_width if config.width is None else config.width
    height = cfg.screen_height if config.height is None else config.height
    rng = random.Random(config.seed)
    console = create_console(base_dir)
    console.log.log("crimson: boot start")
    console.log.log(
        f"config: {cfg.screen_width}x{cfg.screen_height} windowed={cfg.windowed_flag}"
    )
    console.log.flush()
    state = GameState(base_dir=base_dir, rng=rng, config=cfg, console=console)
    view: View = BootView(state)
    run_view(
        view,
        width=width,
        height=height,
        title="Crimsonland",
        fps=config.fps,
    )
