from __future__ import annotations

import math
from typing import Protocol

from grim.geom import Vec2

from ..projectiles import ProjectileTypeId
from ..sim.state_types import GameplayState, PlayerState
from ..weapons import weapon_entry_for_projectile_type_id


class _HasPos(Protocol):
    pos: Vec2


def owner_id_for_player(player_index: int) -> int:
    # crimsonland.exe uses -1/-2/-3 for players (and sometimes -100 in demo paths).
    return -1 - int(player_index)


def owner_id_for_player_projectiles(state: GameplayState, player_index: int) -> int:
    if not state.friendly_fire_enabled:
        return -100
    return owner_id_for_player(player_index)


def projectile_meta_for_type_id(type_id: int) -> float:
    entry = weapon_entry_for_projectile_type_id(int(type_id))
    meta = entry.projectile_meta if entry is not None else None
    return float(meta if meta is not None else 45.0)


def _fire_bullets_active(players: list[PlayerState] | None) -> bool:
    # Native `projectile_spawn` checks `player_state_table.fire_bullets_timer` and `player2_fire_bullets_timer`
    # (i.e. the first two players).
    if not players:
        return False
    for player in players[:2]:
        if float(player.fire_bullets_timer) > 0.0:
            return True
    return False


def projectile_spawn(
    state: GameplayState,
    *,
    players: list[PlayerState] | None,
    pos: Vec2,
    angle: float,
    type_id: int,
    owner_id: int,
    hits_players: bool = False,
) -> int:
    # Mirror `projectile_spawn` (0x00420440) Fire Bullets override.
    type_id = int(type_id)
    owner_id = int(owner_id)
    if (
        (not state.bonus_spawn_guard)
        and owner_id in (-100, -1, -2, -3)
        and type_id != int(ProjectileTypeId.FIRE_BULLETS)
        and _fire_bullets_active(players)
    ):
        type_id = int(ProjectileTypeId.FIRE_BULLETS)

    meta = projectile_meta_for_type_id(type_id)
    return state.projectiles.spawn(
        pos=pos,
        angle=float(angle),
        type_id=int(type_id),
        owner_id=int(owner_id),
        base_damage=float(meta),
        hits_players=bool(hits_players),
    )


def spawn_projectile_ring(
    state: GameplayState,
    origin: _HasPos,
    *,
    count: int,
    angle_offset: float,
    type_id: int,
    owner_id: int,
    players: list[PlayerState] | None = None,
) -> None:
    if count <= 0:
        return
    step = math.tau / float(count)
    for idx in range(count):
        projectile_spawn(
            state,
            players=players,
            pos=origin.pos,
            angle=float(idx) * step + float(angle_offset),
            type_id=int(type_id),
            owner_id=int(owner_id),
        )
