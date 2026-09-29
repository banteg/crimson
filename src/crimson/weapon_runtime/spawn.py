from __future__ import annotations

from typing import TYPE_CHECKING

from grim.geom import Vec2

from ..math_parity import NATIVE_TAU, f32, x87_pc24_add, x87_pc24_div, x87_pc24_mul
from ..owner_id import OWNER_LOCAL_PLAYER
from ..projectiles.types import ProjectileTemplateId
from ..sim.state_types import PlayerState

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState



def projectile_spawn(
    state: GameplayState,
    *,
    players: list[PlayerState],
    pos: Vec2,
    angle: float,
    type_id: ProjectileTemplateId,
    owner_id: int,
    owner_player_index: int,
) -> int:
    """Port of `projectile_spawn` (0x00420440): a player's shot counts as fired and becomes Fire Bullets."""

    # Native lists -100, -1, -2 and -3, so a fourth player's friendly-fire shots skip it; the rewrite takes any player.
    if state.preserve_bugs:
        uses_player_projectile_path = owner_id == OWNER_LOCAL_PLAYER or -3 <= owner_id <= -1
    else:
        uses_player_projectile_path = owner_id < 0
    if not state.bonus_spawn_guard and uses_player_projectile_path:
        # Native loops once more after converting, so a converted shot counts twice.
        while True:
            state.shots_fired += 1
            if type_id == ProjectileTemplateId.FIRE_BULLETS:
                break
            # Native reads both players' timers whoever fired; the rewrite reads the shooter's.
            if state.preserve_bugs:
                fire_bullets_active = any(player.fire_bullets_timer > 0.0 for player in players[:2])
            else:
                fire_bullets_active = players[owner_player_index].fire_bullets_timer > 0.0
            if not fire_bullets_active:
                break
            type_id = ProjectileTemplateId.FIRE_BULLETS

    return state.projectiles.spawn(
        pos=pos,
        angle=float(angle),
        type_id=type_id,
        owner_id=owner_id,
    )


def spawn_projectile_ring(
    state: GameplayState,
    origin_pos: Vec2,
    *,
    count: int,
    angle_offset: float,
    type_id: ProjectileTemplateId,
    owner_id: int,
    owner_player_index: int,
    players: list[PlayerState],
) -> None:
    if count <= 0:
        return
    # Native ring loops push `(float)i * step + offset` at PC24 with
    # `step = 6.2831855f / (float)count` (Angry Reloader 0x00415188; Fireblast
    # bakes 0.3926991f for its 16-ring).
    step = x87_pc24_div(NATIVE_TAU, float(count))
    offset = f32(angle_offset)
    for idx in range(count):
        projectile_spawn(
            state,
            players=players,
            pos=origin_pos,
            angle=x87_pc24_add(x87_pc24_mul(float(idx), step), offset),
            type_id=type_id,
            owner_id=owner_id,
            owner_player_index=owner_player_index,
        )
