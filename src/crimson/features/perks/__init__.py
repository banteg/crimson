from __future__ import annotations

"""Perk-specific deterministic hooks used by the world-step pipeline."""

from .registry import PLAYER_DEATH_HOOKS, WORLD_DT_STEPS

__all__ = ["PLAYER_DEATH_HOOKS", "WORLD_DT_STEPS"]
