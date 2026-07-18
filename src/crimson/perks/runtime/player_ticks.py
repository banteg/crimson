from __future__ import annotations

from grim.geom import Vec2

from ...sim.state_types import GameplayState, PlayerState
from .manifest import PLAYER_PERK_TICK_STEPS
from .player_tick_context import (
    OwnerRefForPlayerFn,
    OwnerRefForPlayerProjectilesFn,
    PlayerPerkTickCtx,
    ProjectileSpawnFn,
)

_PLAYER_PERK_TICK_STEPS = PLAYER_PERK_TICK_STEPS


def apply_player_perk_ticks(
    *,
    player: PlayerState,
    player_pos_before_move: Vec2,
    dt: float,
    state: GameplayState,
    players: list[PlayerState] | None,
    owner_ref_for_player: OwnerRefForPlayerFn,
    owner_ref_for_player_projectiles: OwnerRefForPlayerProjectilesFn,
    projectile_spawn: ProjectileSpawnFn,
) -> None:
    perk_player = players[0] if state.preserve_bugs and players else player
    ctx = PlayerPerkTickCtx(
        state=state,
        player=player,
        perk_player=perk_player,
        player_pos_before_move=player_pos_before_move,
        players=players,
        dt=dt,
        owner_ref_for_player=owner_ref_for_player,
        owner_ref_for_player_projectiles=owner_ref_for_player_projectiles,
        projectile_spawn=projectile_spawn,
    )
    for step in _PLAYER_PERK_TICK_STEPS:
        step(ctx)
