from __future__ import annotations

from typing import TYPE_CHECKING

from crimson.perks.impl.fire_cough import tick_fire_cough
from crimson.perks.impl.hot_tempered import tick_hot_tempered
from crimson.perks.impl.living_fortress import tick_living_fortress
from crimson.perks.impl.man_bomb import tick_man_bomb
from grim.geom import Vec2

from ...sim.state_types import PlayerState
from .player_tick_context import (
    OwnerRefForPlayerFn,
    OwnerRefForPlayerProjectilesFn,
    PlayerPerkTickCtx,
    ProjectileSpawnFn,
)

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState


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
    # Native phase order is observable through shared timers and RNG.
    tick_man_bomb(ctx)
    tick_living_fortress(ctx)
    tick_fire_cough(ctx)
    tick_hot_tempered(ctx)
