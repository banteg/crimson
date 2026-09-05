from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

import msgspec

from grim.geom import Vec2

from ...owner_ref import OwnerRef
from ...sim.state_types import PlayerState

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState


ProjectileSpawnFn = Callable[..., int]
OwnerRefForPlayerFn = Callable[[int], OwnerRef]
type OwnerRefForPlayerProjectilesFn = Callable[[GameplayState, int], OwnerRef]


class PlayerPerkTickCtx(msgspec.Struct):
    state: GameplayState
    player: PlayerState
    perk_player: PlayerState
    player_pos_before_move: Vec2
    players: list[PlayerState] | None
    dt: float
    owner_ref_for_player: OwnerRefForPlayerFn
    owner_ref_for_player_projectiles: OwnerRefForPlayerProjectilesFn
    projectile_spawn: ProjectileSpawnFn
