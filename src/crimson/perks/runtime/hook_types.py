from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Protocol

from .apply_context import PerkApplyHandler
from .effects_context import PerksUpdateEffectsCtx
from ..ids import PerkId
from .player_tick_context import PlayerPerkTickCtx

if TYPE_CHECKING:
    from ...creatures.runtime import CreatureDeath, CreaturePool
    from ...effects import FxQueue
    from ...sim.state_types import GameplayState, PlayerState


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
class PerkHooks:
    perk_id: PerkId
    apply_handler: PerkApplyHandler | None = None
    world_dt_step: WorldDtStep | None = None
    player_tick_steps: tuple[PlayerPerkTickStep, ...] = ()
    effects_steps: tuple[PerksUpdateEffectsStep, ...] = ()
    player_death_hook: PlayerDeathHook | None = None
