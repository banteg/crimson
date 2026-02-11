from __future__ import annotations

"""Ordered perk runtime hook registries for deterministic sim dispatch."""

from typing import TYPE_CHECKING, Callable, Protocol

from .death_clock_effect import update_death_clock
from .effects_context import PerksUpdateEffectsCtx
from .evil_eyes_effect import update_evil_eyes_target
from .fire_cough import tick_fire_cough
from .hot_tempered import tick_hot_tempered
from .jinxed_effect import update_jinxed, update_jinxed_timer
from .lean_mean_exp_machine_effect import update_lean_mean_exp_machine
from .living_fortress import tick_living_fortress
from .man_bomb import tick_man_bomb
from .player_bonus_timers_effect import update_player_bonus_timers
from .player_tick_context import PlayerPerkTickCtx
from .pyrokinetic_effect import update_pyrokinetic
from .reflex_boosted import apply_reflex_boosted_dt
from .regeneration_effect import update_regeneration

if TYPE_CHECKING:
    from ..creatures.runtime import CreatureDeath, CreaturePool
    from ..effects import FxQueue
    from ..sim.state_types import GameplayState, PlayerState


class PlayerDeathHook(Protocol):
    def __call__(
        self,
        *,
        state: GameplayState,
        creatures: CreaturePool,
        players: list[PlayerState],
        player: PlayerState,
        dt: float,
        world_size: float,
        detail_preset: int,
        fx_queue: FxQueue,
        deaths: list[CreatureDeath],
    ) -> None: ...


PlayerPerkTickStep = Callable[[PlayerPerkTickCtx], None]
PerksUpdateEffectsStep = Callable[[PerksUpdateEffectsCtx], None]


def _apply_final_revenge_on_player_death_lazy(
    *,
    state: GameplayState,
    creatures: CreaturePool,
    players: list[PlayerState],
    player: PlayerState,
    dt: float,
    world_size: float,
    detail_preset: int,
    fx_queue: FxQueue,
    deaths: list[CreatureDeath],
) -> None:
    # Delay import to avoid gameplay <-> creature runtime import cycles at startup.
    from .final_revenge import apply_final_revenge_on_player_death

    apply_final_revenge_on_player_death(
        state=state,
        creatures=creatures,
        players=players,
        player=player,
        dt=dt,
        world_size=world_size,
        detail_preset=detail_preset,
        fx_queue=fx_queue,
        deaths=deaths,
    )

WORLD_DT_STEPS = (apply_reflex_boosted_dt,)
PLAYER_DEATH_HOOKS: tuple[PlayerDeathHook, ...] = (_apply_final_revenge_on_player_death_lazy,)

PLAYER_PERK_TICK_STEPS: tuple[PlayerPerkTickStep, ...] = (
    tick_man_bomb,
    tick_living_fortress,
    tick_fire_cough,
    tick_hot_tempered,
)

PERKS_UPDATE_EFFECT_STEPS: tuple[PerksUpdateEffectsStep, ...] = (
    update_player_bonus_timers,
    update_regeneration,
    update_lean_mean_exp_machine,
    update_death_clock,
    update_evil_eyes_target,
    update_pyrokinetic,
    update_jinxed_timer,
    update_jinxed,
)
