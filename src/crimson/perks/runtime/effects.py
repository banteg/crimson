from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from crimson.perks.impl.death_clock import update_death_clock
from crimson.perks.impl.evil_eyes_effect import update_evil_eyes_target
from crimson.perks.impl.jinxed_effect import update_jinxed, update_jinxed_timer
from crimson.perks.impl.lean_mean_exp_machine_effect import update_lean_mean_exp_machine
from crimson.perks.impl.pyrokinetic_effect import update_pyrokinetic
from crimson.perks.impl.regeneration_effect import update_regeneration
from crimson.perks.runtime.player_bonus_timers import update_player_bonus_timers

from ...effects import FxQueue
from ...sim.state_types import PlayerState
from .effects_context import PerksUpdateEffectsCtx

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState

    from ...creatures.runtime import CreatureState


def perks_update_effects(
    state: GameplayState,
    players: list[PlayerState],
    dt: float,
    *,
    creatures: Sequence[CreatureState],
    fx_queue: FxQueue,
) -> None:
    """Apply frame-based perk effect updates.

    Port subset of `perks_update_effects` (0x00406b40).
    """

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
    # Native phase order is observable through shared timers and RNG.
    update_player_bonus_timers(ctx)
    update_regeneration(ctx)
    update_lean_mean_exp_machine(ctx)
    update_death_clock(ctx)
    update_evil_eyes_target(ctx)
    update_pyrokinetic(ctx)
    update_jinxed_timer(ctx)
    update_jinxed(ctx)
