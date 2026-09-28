from __future__ import annotations

from typing import TYPE_CHECKING

from grim.geom import Vec2

from ..math_parity import NATIVE_TAU, f32, x87_pc24_add, x87_pc24_div, x87_pc24_mul
from ..owner_ref import OwnerRef
from ..projectiles.types import ProjectileTemplateId
from ..sim.state_types import PlayerState

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState



def owner_ref_for_player(player_index: int) -> OwnerRef:
    return OwnerRef.from_player(int(player_index))


def owner_ref_for_player_projectiles(state: GameplayState, player_index: int) -> OwnerRef:
    if not state.friendly_fire_enabled:
        return OwnerRef.from_local_player(0)
    return owner_ref_for_player(player_index)


def _uses_native_player_projectile_path(owner: OwnerRef) -> bool:
    legacy_owner = int(owner.to_legacy())
    return legacy_owner == -100 or -3 <= legacy_owner <= -1


def projectile_spawn(
    state: GameplayState,
    *,
    players: list[PlayerState],
    pos: Vec2,
    angle: float,
    type_id: ProjectileTemplateId,
    owner: OwnerRef,
    owner_player_index: int,
    hits_players: bool = False,
) -> int:
    """Port of `projectile_spawn` (0x00420440): a player's shot counts as fired and becomes Fire Bullets."""

    uses_player_projectile_path = owner.is_player() and (
        not state.preserve_bugs or _uses_native_player_projectile_path(owner)
    )
    if not state.bonus_spawn_guard and uses_player_projectile_path:
        # Native loops once more after converting, so a converted shot counts twice.
        while True:
            state.shots_fired[owner_player_index] += 1
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
        owner=owner,
        hits_players=bool(hits_players),
    )


def spawn_projectile_ring(
    state: GameplayState,
    origin_pos: Vec2,
    *,
    count: int,
    angle_offset: float,
    type_id: ProjectileTemplateId,
    owner: OwnerRef,
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
            owner=owner,
            owner_player_index=owner_player_index,
        )
