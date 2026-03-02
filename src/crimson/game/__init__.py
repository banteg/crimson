from __future__ import annotations

from .types import GameConfig

__all__ = ["GameConfig", "run_game"]


def run_game(config: GameConfig) -> None:
    # Keep package import side effects minimal so UI modules can import
    # `crimson.game.types` without pulling in the full runtime graph.
    from .runtime import run_game as _run_game

    _run_game(config)
