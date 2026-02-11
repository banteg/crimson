from __future__ import annotations

"""Ordered perk runtime hook registries for deterministic sim dispatch."""

from .runtime_manifest import (
    GLOBAL_PERKS_UPDATE_EFFECT_STEPS,
    PERK_RUNTIME_HOOKS_IN_ORDER,
    PerksUpdateEffectsStep,
    PlayerDeathHook,
    PlayerPerkTickStep,
    WorldDtStep,
)

WORLD_DT_STEPS: tuple[WorldDtStep, ...] = tuple(
    hook.world_dt_step for hook in PERK_RUNTIME_HOOKS_IN_ORDER if hook.world_dt_step is not None
)

PLAYER_DEATH_HOOKS: tuple[PlayerDeathHook, ...] = tuple(
    hook.player_death_hook for hook in PERK_RUNTIME_HOOKS_IN_ORDER if hook.player_death_hook is not None
)

PLAYER_PERK_TICK_STEPS: tuple[PlayerPerkTickStep, ...] = tuple(
    step for hook in PERK_RUNTIME_HOOKS_IN_ORDER for step in hook.player_tick_steps
)

PERKS_UPDATE_EFFECT_STEPS: tuple[PerksUpdateEffectsStep, ...] = GLOBAL_PERKS_UPDATE_EFFECT_STEPS + tuple(
    step for hook in PERK_RUNTIME_HOOKS_IN_ORDER for step in hook.effects_steps
)
