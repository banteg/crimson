from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol

import msgspec

from ..ids import PerkId
from .apply_context import PerkApplyHandler
from .effects_context import PerksUpdateEffectsCtx
from .player_tick_context import PlayerPerkTickCtx

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState

    from ...creatures.runtime import CreatureDeath, CreaturePool
    from ...effects import FxQueue
    from ...sim.state_types import PlayerState


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


class PerkHooks(msgspec.Struct, frozen=True):
    perk_id: PerkId
    apply_handler: PerkApplyHandler | None = None
    world_dt_step: WorldDtStep | None = None
    player_tick_steps: tuple[PlayerPerkTickStep, ...] = ()
    effects_steps: tuple[PerksUpdateEffectsStep, ...] = ()
    player_death_hook: PlayerDeathHook | None = None
