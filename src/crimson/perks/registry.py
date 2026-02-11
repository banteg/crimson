from __future__ import annotations

"""Ordered perk hook registries for deterministic world-step dispatch."""

from . import runtime_registry as _runtime_registry

WORLD_DT_STEPS = _runtime_registry.WORLD_DT_STEPS
PLAYER_DEATH_HOOKS = _runtime_registry.PLAYER_DEATH_HOOKS

__all__ = ("WORLD_DT_STEPS", "PLAYER_DEATH_HOOKS")
