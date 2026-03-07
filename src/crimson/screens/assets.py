from __future__ import annotations

from grim.assets import RuntimeResources

from ..game.types import GameState


def require_runtime_resources(state: GameState) -> RuntimeResources:
    if state.resources is None:
        raise RuntimeError("runtime resources are not loaded")
    return state.resources
