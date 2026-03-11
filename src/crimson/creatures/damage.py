from __future__ import annotations

import math
from collections.abc import Callable

import msgspec

from grim.color import RGBA
from grim.geom import Vec2
from grim.rand import CrandLike

from ..effects import EffectPool
from ..effects_atlas import EffectId
from ..math_parity import f32
from ..owner_ref import OwnerRef
from ..perks import PerkId
from ..perks.helpers import perk_active
from ..sim.state_types import PlayerState
from .damage_types import CreatureDamageType
from .runtime import CREATURE_LIFECYCLE_ALIVE, CreatureState
from .spawn import CreatureFlags


def _any_player_has_perk(players: list[PlayerState], perk_id: PerkId) -> bool:
    return any(perk_active(player, perk_id) for player in players)


class _CreatureDamageCtx(msgspec.Struct):
    creature: CreatureState
    damage: float
    damage_type: int
    impulse: Vec2
    owner: OwnerRef
    dt: float
    players: list[PlayerState]
    rng: CrandLike


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
    jitter = float((ctx.rng.rand() & 0x7F) - 0x40) * 0.002
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
    ctx.rng.rand()


def _damage_lethal_ranged_shock_burst(
    *,
    creature: CreatureState,
    rng: CrandLike,
    effects: EffectPool | None,
    detail_preset: int,
) -> None:
    """Port the `creature_apply_damage` lethal branch for `flags & 0x10`."""
    if (creature.flags & CreatureFlags.RANGED_ATTACK_SHOCK) == 0:
        return
    for _ in range(5):
        rotation = float(rng.rand() & 0x7F) * 0.049087387
        vel = Vec2(
            float((rng.rand() & 0x7F) - 0x40),
            float((rng.rand() & 0x7F) - 0x40),
        )
        scale_step = float(rng.rand() % 140) * 0.01 + 0.3
        if effects is None:
            continue
        effects.spawn(
            effect_id=int(EffectId.BURST),
            pos=creature.pos,
            vel=vel,
            rotation=rotation,
            scale=1.0,
            half_width=36.0,
            half_height=36.0,
            age=0.0,
            lifetime=0.7,
            flags=0x1D,
            color=RGBA(0.8, 0.8, 0.3, 0.5),
            rotation_step=0.0,
            scale_step=scale_step,
            detail_preset=int(detail_preset),
        )


_CREATURE_DAMAGE_PRE_STEPS: dict[int, tuple[_CreatureDamageStep, ...]] = {
    CreatureDamageType.BULLET: (
        _damage_type1_uranium_filled_bullets,
        _damage_type1_living_fortress,
        _damage_type1_barrel_greaser,
        _damage_type1_doctor,
    ),
}

_CREATURE_DAMAGE_GLOBAL_PRE_STEPS: dict[int, tuple[_CreatureDamageStep, ...]] = {
    CreatureDamageType.ION: (_damage_type7_ion_gun_master,),
}


_CREATURE_DAMAGE_ALIVE_STEPS: dict[int, tuple[_CreatureDamageStep, ...]] = {
    CreatureDamageType.FIRE: (_damage_type4_pyromaniac,),
}


def creature_apply_damage(
    creature: CreatureState,
    *,
    damage_amount: float,
    damage_type: int,
    impulse: Vec2,
    owner: OwnerRef,
    dt: float,
    players: list[PlayerState],
    rng: CrandLike,
    effects: EffectPool | None = None,
    detail_preset: int = 5,
) -> bool:
    """Apply damage to a creature, returning True if the hit killed it.

    This is a partial port of `creature_apply_damage` (FUN_004207c0).

    Notes:
    - Death side-effects are handled by the caller.
    - `damage_type` is a native integer category; call sites must supply it.
    """

    creature.last_hit_owner = owner
    creature.hit_flash_timer = 0.2

    ctx = _CreatureDamageCtx(
        creature=creature,
        damage=float(damage_amount),
        damage_type=int(damage_type),
        impulse=impulse,
        owner=owner,
        dt=float(dt),
        players=players,
        rng=rng,
    )

    for step in _CREATURE_DAMAGE_GLOBAL_PRE_STEPS.get(ctx.damage_type, ()):
        step(ctx)

    for step in _CREATURE_DAMAGE_PRE_STEPS.get(ctx.damage_type, ()):
        step(ctx)
    if ctx.damage_type == CreatureDamageType.BULLET:
        _damage_type1_heading_jitter(ctx)

    if creature.hp <= 0.0:
        if dt > 0.0:
            creature.lifecycle_stage = float(
                f32(float(creature.lifecycle_stage) - float(f32(float(dt) * 15.0))),
            )
        return True

    for step in _CREATURE_DAMAGE_ALIVE_STEPS.get(ctx.damage_type, ()):
        step(ctx)

    creature.hp -= float(ctx.damage)
    creature.vel = creature.vel - ctx.impulse

    if creature.hp <= 0.0:
        if dt > 0.0:
            creature.lifecycle_stage = float(
                f32(float(creature.lifecycle_stage) - float(f32(float(dt)))),
            )
        else:
            creature.lifecycle_stage = float(f32(float(creature.lifecycle_stage) - 0.001))
        creature.vel = creature.vel - impulse * 2.0
        _damage_lethal_ranged_shock_burst(
            creature=creature,
            rng=rng,
            effects=effects,
            detail_preset=int(detail_preset),
        )
        return True

    return False


def creature_apply_damage_with_lethal_followup(
    creature: CreatureState,
    *,
    damage_amount: float,
    damage_type: int,
    impulse: Vec2,
    owner: OwnerRef,
    dt: float,
    players: list[PlayerState],
    rng: CrandLike,
    effects: EffectPool | None = None,
    detail_preset: int = 5,
    on_lethal: Callable[[], None],
) -> bool:
    """Apply damage and run a required lethal follow-up exactly on death transition.

    This helper keeps lethal bookkeeping adjacent to damage application so runtime
    call sites cannot accidentally skip death handling side effects.
    """

    death_start_needed = float(creature.hp) > 0.0 and float(creature.lifecycle_stage) == CREATURE_LIFECYCLE_ALIVE
    killed = creature_apply_damage(
        creature,
        damage_amount=float(damage_amount),
        damage_type=int(damage_type),
        impulse=impulse,
        owner=owner,
        dt=float(dt),
        players=players,
        rng=rng,
        effects=effects,
        detail_preset=int(detail_preset),
    )
    if killed and death_start_needed:
        on_lethal()
        return True
    return False
