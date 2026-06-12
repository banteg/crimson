from __future__ import annotations

import math

from grim.geom import Vec2

from ..math_parity import f32
from ..owner_ref import OwnerRef
from ..projectiles.types import ProjectileTemplateId
from ..sim.state_types import GameplayState, PlayerState
from ..weapons import weapon_entry_for_projectile_type_id


def owner_ref_for_player(player_index: int) -> OwnerRef:
    return OwnerRef.from_player(int(player_index))


def owner_ref_for_player_projectiles(state: GameplayState, player_index: int) -> OwnerRef:
    if not state.friendly_fire_enabled:
        return OwnerRef.from_local_player(0)
    return owner_ref_for_player(player_index)


def travel_budget_for_type_id(type_id: ProjectileTemplateId) -> float:
    return float(weapon_entry_for_projectile_type_id(type_id).travel_budget)


def _resolve_player_slot(players: list[PlayerState], *, player_index: int) -> int | None:
    target_index = int(player_index)
    if 0 <= target_index < len(players):
        direct = players[target_index]
        if int(direct.index) == target_index:
            return int(target_index)
    for slot, player in enumerate(players):
        if int(player.index) == target_index:
            return int(slot)
    return None


def _shots_fired_player_index(
    *,
    state: GameplayState,
    players: list[PlayerState] | None,
    owner: OwnerRef,
    owner_player_index: int | None,
) -> int | None:
    if owner_player_index is not None:
        player_index = int(owner_player_index)
        if 0 <= player_index < len(state.shots_fired):
            return int(player_index)

    if owner.is_player() and not (owner.local_host and owner.index == 0):
        player_index = int(owner.index)
        if 0 <= player_index < len(state.shots_fired):
            return int(player_index)

    if owner.local_host and owner.index == 0 and players and len(players) == 1:
        player_index = int(players[0].index)
        if 0 <= player_index < len(state.shots_fired):
            return int(player_index)

    return None


def _fire_bullets_active(
    players: list[PlayerState] | None,
    *,
    state: GameplayState,
    owner: OwnerRef,
    owner_player_index: int | None,
) -> bool:
    if not players:
        return False

    # Native `projectile_spawn` checks player-1/player-2 Fire Bullets timers
    # globally, regardless of projectile ownership.
    if bool(state.preserve_bugs):
        return any(float(player.fire_bullets_timer) > 0.0 for player in players[:2])

    resolved_owner_slot: int | None = None
    if owner_player_index is not None:
        resolved_owner_slot = _resolve_player_slot(players, player_index=int(owner_player_index))
    elif owner.is_player() and not (owner.local_host and owner.index == 0):
        resolved_owner_slot = _resolve_player_slot(players, player_index=int(owner.index))
    elif owner.local_host and owner.index == 0 and len(players) == 1:
        # Callers that only pass one player are explicitly indicating the owner
        # context (for example OwnerRef.from_local_player(0) with friendly fire disabled).
        resolved_owner_slot = 0

    if resolved_owner_slot is None:
        return False
    if not (0 <= resolved_owner_slot < len(players)):
        return False
    return float(players[resolved_owner_slot].fire_bullets_timer) > 0.0


def projectile_spawn(
    state: GameplayState,
    *,
    players: list[PlayerState] | None,
    pos: Vec2,
    angle: float,
    type_id: ProjectileTemplateId,
    owner: OwnerRef,
    owner_player_index: int | None = None,
    hits_players: bool = False,
) -> int:
    # Mirror `projectile_spawn` (0x00420440) Fire Bullets override.
    if (not state.bonus_spawn_guard) and owner.is_player():
        while True:
            player_index = _shots_fired_player_index(
                state=state,
                players=players,
                owner=owner,
                owner_player_index=owner_player_index,
            )
            state.shots_fired_total += 1
            if player_index is not None:
                state.shots_fired[player_index] += 1
            if type_id == ProjectileTemplateId.FIRE_BULLETS:
                break
            if not _fire_bullets_active(
                players,
                state=state,
                owner=owner,
                owner_player_index=owner_player_index,
            ):
                break
            type_id = ProjectileTemplateId.FIRE_BULLETS

    meta = travel_budget_for_type_id(type_id)
    return state.projectiles.spawn(
        pos=pos,
        angle=float(angle),
        type_id=type_id,
        owner=owner,
        travel_budget=float(meta),
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
    owner_player_index: int | None = None,
    players: list[PlayerState] | None = None,
) -> None:
    if count <= 0:
        return
    # Native multiplies the loop index by an f32 step literal (e.g. 0.3926991f
    # for the 16-ring); keep the f32 rounding so the ring angles match.
    step = float(f32(math.tau / float(count)))
    for idx in range(count):
        projectile_spawn(
            state,
            players=players,
            pos=origin_pos,
            angle=float(f32(float(idx) * step)) + float(angle_offset),
            type_id=type_id,
            owner=owner,
            owner_player_index=owner_player_index,
        )
