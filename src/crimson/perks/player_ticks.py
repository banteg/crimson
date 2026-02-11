from __future__ import annotations

from typing import Callable

from ..sim.state_types import GameplayState, PlayerState
from .fire_cough import tick_fire_cough
from .hot_tempered import tick_hot_tempered
from .living_fortress import tick_living_fortress
from .man_bomb import tick_man_bomb
from .player_tick_context import (
    OwnerIdForPlayerFn,
    OwnerIdForPlayerProjectilesFn,
    PlayerPerkTickCtx,
    ProjectileSpawnFn,
)

PlayerPerkTickStep = Callable[[PlayerPerkTickCtx], None]

_PLAYER_PERK_TICK_STEPS: tuple[PlayerPerkTickStep, ...] = (
    tick_man_bomb,
    tick_living_fortress,
    tick_fire_cough,
    tick_hot_tempered,
)


def apply_player_perk_ticks(
    *,
    player: PlayerState,
    dt: float,
    state: GameplayState,
    players: list[PlayerState] | None,
    stationary: bool,
    owner_id_for_player: OwnerIdForPlayerFn,
    owner_id_for_player_projectiles: OwnerIdForPlayerProjectilesFn,
    projectile_spawn: ProjectileSpawnFn,
) -> None:
    ctx = PlayerPerkTickCtx(
        state=state,
        player=player,
        players=players,
        dt=dt,
        stationary=stationary,
        owner_id_for_player=owner_id_for_player,
        owner_id_for_player_projectiles=owner_id_for_player_projectiles,
        projectile_spawn=projectile_spawn,
    )
    for step in _PLAYER_PERK_TICK_STEPS:
        step(ctx)
