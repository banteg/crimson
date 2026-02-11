from __future__ import annotations

from typing import Sequence

from ..effects import FxQueue
from ..sim.state_types import GameplayState, PlayerState
from .effects_context import CreatureForPerks, PerksUpdateEffectsCtx, creature_find_in_radius
from .runtime_registry import PERKS_UPDATE_EFFECT_STEPS

# Backward-compatible re-export used by HUD target hover wiring.
_creature_find_in_radius = creature_find_in_radius

_PERKS_UPDATE_EFFECT_STEPS = PERKS_UPDATE_EFFECT_STEPS


def perks_update_effects(
    state: GameplayState,
    players: list[PlayerState],
    dt: float,
    *,
    creatures: Sequence[CreatureForPerks] | None = None,
    fx_queue: FxQueue | None = None,
) -> None:
    """Port subset of `perks_update_effects` (0x00406b40)."""

    dt = float(dt)
    if dt <= 0.0:
        return
    ctx = PerksUpdateEffectsCtx(
        state=state,
        players=players,
        dt=dt,
        creatures=creatures,
        fx_queue=fx_queue,
    )
    for step in _PERKS_UPDATE_EFFECT_STEPS:
        step(ctx)
