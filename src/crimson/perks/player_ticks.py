from __future__ import annotations

from ..sim.state_types import GameplayState, PlayerState
from .player_tick_context import (
    OwnerIdForPlayerFn,
    OwnerIdForPlayerProjectilesFn,
    PlayerPerkTickCtx,
    ProjectileSpawnFn,
)
from .manifest import PLAYER_PERK_TICK_STEPS

_PLAYER_PERK_TICK_STEPS = PLAYER_PERK_TICK_STEPS


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
