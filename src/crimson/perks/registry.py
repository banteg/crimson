from __future__ import annotations

"""Ordered perk hook registries for deterministic world-step dispatch."""

from .final_revenge import apply_final_revenge_on_player_death
from .reflex_boosted import apply_reflex_boosted_dt

WORLD_DT_STEPS = (apply_reflex_boosted_dt,)
PLAYER_DEATH_HOOKS = (apply_final_revenge_on_player_death,)

