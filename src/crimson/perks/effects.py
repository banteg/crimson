from __future__ import annotations

from typing import Callable, Sequence

from ..effects import FxQueue
from ..sim.state_types import GameplayState, PlayerState
from .death_clock_effect import update_death_clock
from .effects_context import CreatureForPerks, PerksUpdateEffectsCtx, creature_find_in_radius
from .evil_eyes_effect import update_evil_eyes_target
from .jinxed_effect import update_jinxed, update_jinxed_timer
from .lean_mean_exp_machine_effect import update_lean_mean_exp_machine
from .player_bonus_timers_effect import update_player_bonus_timers
from .pyrokinetic_effect import update_pyrokinetic
from .regeneration_effect import update_regeneration

PerksUpdateEffectsStep = Callable[[PerksUpdateEffectsCtx], None]

# Backward-compatible re-export used by HUD target hover wiring.
_creature_find_in_radius = creature_find_in_radius

_PERKS_UPDATE_EFFECT_STEPS: tuple[PerksUpdateEffectsStep, ...] = (
    update_player_bonus_timers,
    update_regeneration,
    update_lean_mean_exp_machine,
    update_death_clock,
    update_evil_eyes_target,
    update_pyrokinetic,
    update_jinxed_timer,
    update_jinxed,
)


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
