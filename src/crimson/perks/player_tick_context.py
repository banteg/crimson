from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..sim.state_types import GameplayState, PlayerState

ProjectileSpawnFn = Callable[..., int]
OwnerIdForPlayerFn = Callable[[int], int]
OwnerIdForPlayerProjectilesFn = Callable[[GameplayState, int], int]


@dataclass(slots=True)
class PlayerPerkTickCtx:
    state: GameplayState
    player: PlayerState
    players: list[PlayerState] | None
    dt: float
    stationary: bool
    owner_id_for_player: OwnerIdForPlayerFn
    owner_id_for_player_projectiles: OwnerIdForPlayerProjectilesFn
    projectile_spawn: ProjectileSpawnFn
