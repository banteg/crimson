from __future__ import annotations

import math
from typing import Callable

from ..gameplay import PlayerState, perk_active
from ..perks import PerkId
from .runtime import CREATURE_HITBOX_ALIVE, CreatureState
from .spawn import CreatureFlags


def _owner_id_to_player_index(owner_id: int) -> int | None:
    if owner_id == -100:
        return 0
    if owner_id < 0:
        return -1 - owner_id
    return None


def creature_apply_damage(
    creature: CreatureState,
    *,
    damage_amount: float,
    damage_type: int,
    impulse_x: float,
    impulse_y: float,
    owner_id: int,
    dt: float,
    players: list[PlayerState],
    rand: Callable[[], int],
) -> bool:
    """Apply damage to a creature, returning True if the hit killed it.

    This is a partial port of `creature_apply_damage` (FUN_004207c0).

    Notes:
    - Death side-effects are handled by the caller (see Phase 2 in `plan.md`).
    - `damage_type` is a native integer category; call sites must supply it.
    """

    creature.last_hit_owner_id = int(owner_id)
    creature.hit_flash_timer = 0.2

    player_index = _owner_id_to_player_index(owner_id)
    attacker = players[player_index] if player_index is not None and 0 <= player_index < len(players) else None

    damage = float(damage_amount)

    if int(damage_type) == 1 and attacker is not None:
        if perk_active(attacker, PerkId.URANIUM_FILLED_BULLETS):
            damage *= 2.0

        if perk_active(attacker, PerkId.LIVING_FORTRESS):
            for player in players:
                if float(player.health) <= 0.0:
                    continue
                timer = float(player.living_fortress_timer)
                if timer > 0.0:
                    damage *= timer * 0.05 + 1.0

        if perk_active(attacker, PerkId.BARREL_GREASER):
            damage *= 1.4
        if perk_active(attacker, PerkId.DOCTOR):
            damage *= 1.2

        if (creature.flags & CreatureFlags.ANIM_PING_PONG) == 0:
            jitter = float((int(rand()) & 0x7F) - 0x40) * 0.002
            size = max(1e-6, float(creature.size))
            turn = jitter / (size * 0.025)
            turn = max(-math.pi / 2.0, min(math.pi / 2.0, turn))
            creature.heading += turn

    if int(damage_type) == 7 and attacker is not None:
        if perk_active(attacker, PerkId.ION_GUN_MASTER):
            damage *= 1.2

    if creature.hp <= 0.0:
        if dt > 0.0:
            creature.hitbox_size -= float(dt) * 15.0
        return True

    if int(damage_type) == 4 and attacker is not None:
        if perk_active(attacker, PerkId.PYROMANIAC):
            damage *= 1.5
            rand()

    creature.hp -= damage
    creature.vel_x -= float(impulse_x)
    creature.vel_y -= float(impulse_y)

    if creature.hp <= 0.0:
        if dt > 0.0:
            creature.hitbox_size = float(creature.hitbox_size) - float(dt)
        else:
            creature.hitbox_size = float(creature.hitbox_size) - 0.001
        creature.vel_x -= float(impulse_x) * 2.0
        creature.vel_y -= float(impulse_y) * 2.0
        return True

    if creature.hitbox_size != CREATURE_HITBOX_ALIVE and dt > 0.0:
        creature.hitbox_size = CREATURE_HITBOX_ALIVE

    return False
