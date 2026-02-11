from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Callable

from grim.geom import Vec2

from ..perks import PerkId
from ..perks.helpers import perk_active
from ..sim.state_types import PlayerState
from .runtime import CREATURE_HITBOX_ALIVE, CreatureState
from .spawn import CreatureFlags


def _any_player_has_perk(players: list[PlayerState], perk_id: PerkId) -> bool:
    return any(perk_active(player, perk_id) for player in players)


@dataclass(slots=True)
class _CreatureDamageCtx:
    creature: CreatureState
    damage: float
    damage_type: int
    impulse: Vec2
    owner_id: int
    dt: float
    players: list[PlayerState]
    rand: Callable[[], int]


_CreatureDamageStep = Callable[[_CreatureDamageCtx], None]


def _damage_type1_uranium_filled_bullets(ctx: _CreatureDamageCtx) -> None:
    if not _any_player_has_perk(ctx.players, PerkId.URANIUM_FILLED_BULLETS):
        return
    ctx.damage *= 2.0


def _damage_type1_living_fortress(ctx: _CreatureDamageCtx) -> None:
    if not _any_player_has_perk(ctx.players, PerkId.LIVING_FORTRESS):
        return
    for player in ctx.players:
        if float(player.health) <= 0.0:
            continue
        timer = float(player.living_fortress_timer)
        if timer > 0.0:
            ctx.damage *= timer * 0.05 + 1.0


def _damage_type1_barrel_greaser(ctx: _CreatureDamageCtx) -> None:
    if not _any_player_has_perk(ctx.players, PerkId.BARREL_GREASER):
        return
    ctx.damage *= 1.4


def _damage_type1_doctor(ctx: _CreatureDamageCtx) -> None:
    if not _any_player_has_perk(ctx.players, PerkId.DOCTOR):
        return
    ctx.damage *= 1.2


def _damage_type1_heading_jitter(ctx: _CreatureDamageCtx) -> None:
    creature = ctx.creature
    if (creature.flags & CreatureFlags.ANIM_PING_PONG) != 0:
        return
    jitter = float((int(ctx.rand()) & 0x7F) - 0x40) * 0.002
    size = max(1e-6, float(creature.size))
    turn = jitter / (size * 0.025)
    turn = min(math.pi / 2.0, turn)
    creature.heading += turn


def _damage_type7_ion_gun_master(ctx: _CreatureDamageCtx) -> None:
    if any(perk_active(player, PerkId.ION_GUN_MASTER) for player in ctx.players):
        ctx.damage *= 1.2


def _damage_type4_pyromaniac(ctx: _CreatureDamageCtx) -> None:
    if not _any_player_has_perk(ctx.players, PerkId.PYROMANIAC):
        return
    ctx.damage *= 1.5
    ctx.rand()


_CREATURE_DAMAGE_PRE_STEPS: dict[int, tuple[_CreatureDamageStep, ...]] = {
    1: (
        _damage_type1_uranium_filled_bullets,
        _damage_type1_living_fortress,
        _damage_type1_barrel_greaser,
        _damage_type1_doctor,
    ),
}

_CREATURE_DAMAGE_GLOBAL_PRE_STEPS: dict[int, tuple[_CreatureDamageStep, ...]] = {
    7: (_damage_type7_ion_gun_master,),
}


_CREATURE_DAMAGE_ALIVE_STEPS: dict[int, tuple[_CreatureDamageStep, ...]] = {
    4: (_damage_type4_pyromaniac,),
}


def creature_apply_damage(
    creature: CreatureState,
    *,
    damage_amount: float,
    damage_type: int,
    impulse: Vec2,
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

    ctx = _CreatureDamageCtx(
        creature=creature,
        damage=float(damage_amount),
        damage_type=int(damage_type),
        impulse=impulse,
        owner_id=int(owner_id),
        dt=float(dt),
        players=players,
        rand=rand,
    )

    for step in _CREATURE_DAMAGE_GLOBAL_PRE_STEPS.get(ctx.damage_type, ()):
        step(ctx)

    for step in _CREATURE_DAMAGE_PRE_STEPS.get(ctx.damage_type, ()):
        step(ctx)
    if ctx.damage_type == 1:
        _damage_type1_heading_jitter(ctx)

    if creature.hp <= 0.0:
        if dt > 0.0:
            creature.hitbox_size -= float(dt) * 15.0
        return True

    for step in _CREATURE_DAMAGE_ALIVE_STEPS.get(ctx.damage_type, ()):
        step(ctx)

    creature.hp -= float(ctx.damage)
    creature.vel = creature.vel - ctx.impulse

    if creature.hp <= 0.0:
        if dt > 0.0:
            creature.hitbox_size = float(creature.hitbox_size) - float(dt)
        else:
            creature.hitbox_size = float(creature.hitbox_size) - 0.001
        creature.vel = creature.vel - impulse * 2.0
        return True

    if creature.hitbox_size != CREATURE_HITBOX_ALIVE and dt > 0.0:
        creature.hitbox_size = CREATURE_HITBOX_ALIVE

    return False
