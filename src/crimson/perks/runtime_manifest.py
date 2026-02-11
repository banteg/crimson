from __future__ import annotations

"""Perk-owned runtime hook manifest with explicit ordering.

The order in `PERK_RUNTIME_HOOKS_IN_ORDER` is parity-critical.
Phase registries are derived from this manifest by `runtime_registry.py`.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Protocol

from .death_clock_effect import update_death_clock
from .effects_context import PerksUpdateEffectsCtx
from .evil_eyes_effect import update_evil_eyes_target
from .fire_cough import tick_fire_cough
from .hot_tempered import tick_hot_tempered
from .ids import PerkId
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


class WorldDtStep(Protocol):
    def __call__(self, *, dt: float, players: list[PlayerState]) -> float: ...


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


@dataclass(frozen=True, slots=True)
class PerkRuntimeHooks:
    perk_id: PerkId
    world_dt_step: WorldDtStep | None = None
    player_tick_steps: tuple[PlayerPerkTickStep, ...] = ()
    effects_steps: tuple[PerksUpdateEffectsStep, ...] = ()
    player_death_hook: PlayerDeathHook | None = None


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


GLOBAL_PERKS_UPDATE_EFFECT_STEPS: tuple[PerksUpdateEffectsStep, ...] = (
    update_player_bonus_timers,
)


PERK_RUNTIME_HOOKS_IN_ORDER: tuple[PerkRuntimeHooks, ...] = (
    PerkRuntimeHooks(
        perk_id=PerkId.REFLEX_BOOSTED,
        world_dt_step=apply_reflex_boosted_dt,
    ),
    PerkRuntimeHooks(
        perk_id=PerkId.MAN_BOMB,
        player_tick_steps=(tick_man_bomb,),
    ),
    PerkRuntimeHooks(
        perk_id=PerkId.LIVING_FORTRESS,
        player_tick_steps=(tick_living_fortress,),
    ),
    PerkRuntimeHooks(
        perk_id=PerkId.FIRE_CAUGH,
        player_tick_steps=(tick_fire_cough,),
    ),
    PerkRuntimeHooks(
        perk_id=PerkId.HOT_TEMPERED,
        player_tick_steps=(tick_hot_tempered,),
    ),
    PerkRuntimeHooks(
        perk_id=PerkId.REGENERATION,
        effects_steps=(update_regeneration,),
    ),
    PerkRuntimeHooks(
        perk_id=PerkId.LEAN_MEAN_EXP_MACHINE,
        effects_steps=(update_lean_mean_exp_machine,),
    ),
    PerkRuntimeHooks(
        perk_id=PerkId.DEATH_CLOCK,
        effects_steps=(update_death_clock,),
    ),
    PerkRuntimeHooks(
        perk_id=PerkId.EVIL_EYES,
        effects_steps=(update_evil_eyes_target,),
    ),
    PerkRuntimeHooks(
        perk_id=PerkId.PYROKINETIC,
        effects_steps=(update_pyrokinetic,),
    ),
    PerkRuntimeHooks(
        perk_id=PerkId.JINXED,
        effects_steps=(update_jinxed_timer, update_jinxed),
    ),
    PerkRuntimeHooks(
        perk_id=PerkId.FINAL_REVENGE,
        player_death_hook=_apply_final_revenge_on_player_death_lazy,
    ),
)
