from __future__ import annotations

from collections.abc import Callable

import msgspec

from grim.color import RGBA
from grim.geom import Vec2
from grim.rand import CrandLike
from grim.sfx_map import SfxId

from ..effects import EffectPool
from ..effects_atlas import EffectId
from ..math_parity import NATIVE_HALF_PI, f32, x87_pc24_add, x87_pc24_div, x87_pc24_mul, x87_pc24_sub
from ..owner_ref import OwnerRef
from ..perks import PerkId
from ..perks.helpers import perk_active
from ..rng_caller_static import RngCallerStatic
from ..sim.state_types import PlayerState
from .damage_runtime import CreatureDamageRuntime
from .damage_types import CreatureDamageType
from .runtime import CreatureState
from .spawn import CreatureFlags, CreatureTypeId


def _any_player_has_perk(players: list[PlayerState], perk_id: PerkId) -> bool:
    return any(perk_active(player, perk_id) for player in players)


def _damage_perk_active(ctx: _CreatureDamageCtx, perk_id: PerkId) -> bool:
    if ctx.preserve_bugs:
        return bool(ctx.players) and perk_active(ctx.players[0], perk_id)
    return _any_player_has_perk(ctx.players, perk_id)


class _CreatureDamageCtx(msgspec.Struct):
    creature: CreatureState
    damage: float
    damage_type: int
    impulse: Vec2
    owner: OwnerRef
    dt: float
    players: list[PlayerState]
    rng: CrandLike
    preserve_bugs: bool


_CreatureDamageStep = Callable[[_CreatureDamageCtx], None]


_CREATURE_DEATH_SFX: dict[CreatureTypeId, tuple[SfxId, ...]] = {
    CreatureTypeId.ZOMBIE: (
        SfxId.ZOMBIE_DIE_01,
        SfxId.ZOMBIE_DIE_02,
        SfxId.ZOMBIE_DIE_03,
        SfxId.ZOMBIE_DIE_04,
    ),
    CreatureTypeId.LIZARD: (
        SfxId.LIZARD_DIE_01,
        SfxId.LIZARD_DIE_02,
        SfxId.LIZARD_DIE_03,
        SfxId.LIZARD_DIE_04,
    ),
    CreatureTypeId.ALIEN: (
        SfxId.ALIEN_DIE_01,
        SfxId.ALIEN_DIE_02,
        SfxId.ALIEN_DIE_03,
        SfxId.ALIEN_DIE_04,
    ),
    CreatureTypeId.SPIDER_SP1: (
        SfxId.SPIDER_DIE_01,
        SfxId.SPIDER_DIE_02,
        SfxId.SPIDER_DIE_03,
        SfxId.SPIDER_DIE_04,
    ),
    CreatureTypeId.SPIDER_SP2: (
        SfxId.SPIDER_DIE_01,
        SfxId.SPIDER_DIE_02,
        SfxId.SPIDER_DIE_03,
        SfxId.SPIDER_DIE_04,
    ),
}

_TROOPER_DEATH_SFX: tuple[SfxId, ...] = (
    SfxId.TROOPER_DIE_01,
    SfxId.TROOPER_DIE_02,
    SfxId.TROOPER_DIE_03,
)

# Native `gameplay_reset_state` writes trooper death-bank slots 0..2 only, but
# `creature_apply_damage` still indexes the bank with `rand & 3`. The unwritten
# slot remains BSS-zeroed and resolves to native SFX id 0:
# `sfx_trooper_inpain_01`.
_TROOPER_DEATH_SFX_PRESERVE_BUGS: tuple[SfxId, ...] = (
    *_TROOPER_DEATH_SFX,
    SfxId.TROOPER_INPAIN_01,
)


def _damage_type1_uranium_filled_bullets(ctx: _CreatureDamageCtx) -> None:
    if not _damage_perk_active(ctx, PerkId.URANIUM_FILLED_BULLETS):
        return
    ctx.damage = x87_pc24_add(ctx.damage, ctx.damage)


def _damage_type1_living_fortress(ctx: _CreatureDamageCtx) -> None:
    if not _damage_perk_active(ctx, PerkId.LIVING_FORTRESS):
        return
    for player in ctx.players:
        if float(player.health) <= 0.0:
            continue
        timer = float(player.living_fortress_timer)
        if timer > 0.0:
            scale = x87_pc24_add(x87_pc24_mul(timer, f32(0.05)), 1.0)
            ctx.damage = x87_pc24_mul(ctx.damage, scale)


def _damage_type1_barrel_greaser(ctx: _CreatureDamageCtx) -> None:
    if not _damage_perk_active(ctx, PerkId.BARREL_GREASER):
        return
    ctx.damage = x87_pc24_mul(ctx.damage, f32(1.4))


def _damage_type1_doctor(ctx: _CreatureDamageCtx) -> None:
    if not _damage_perk_active(ctx, PerkId.DOCTOR):
        return
    ctx.damage = x87_pc24_mul(ctx.damage, f32(1.2))


def _damage_type1_heading_jitter(ctx: _CreatureDamageCtx) -> None:
    creature = ctx.creature
    if (creature.flags & CreatureFlags.ANIM_PING_PONG) != 0:
        return
    jitter = x87_pc24_mul(
        float((ctx.rng.rand_tagged(RngCallerStatic.CREATURE_APPLY_DAMAGE_HEADING_JITTER) & 0x7F) - 0x40),
        f32(0.002),
    )
    size = max(1e-6, float(creature.size))
    turn = x87_pc24_div(jitter, x87_pc24_mul(size, f32(0.025)))
    # Native clamps against the f32 literal 1.5707964 and stores the sum f32.
    turn = min(float(NATIVE_HALF_PI), turn)
    creature.heading = x87_pc24_add(turn, creature.heading)


def _damage_type7_ion_gun_master(ctx: _CreatureDamageCtx) -> None:
    if _damage_perk_active(ctx, PerkId.ION_GUN_MASTER):
        ctx.damage = x87_pc24_mul(ctx.damage, f32(1.2))


def _damage_type4_pyromaniac(ctx: _CreatureDamageCtx) -> None:
    if not _damage_perk_active(ctx, PerkId.PYROMANIAC):
        return
    ctx.damage = x87_pc24_mul(ctx.damage, f32(1.5))
    ctx.rng.rand_tagged(RngCallerStatic.CREATURE_APPLY_DAMAGE_PYROMANIAC)


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
        rotation = (
            float(rng.rand_tagged(RngCallerStatic.CREATURE_APPLY_DAMAGE_SHOCK_BURST_ROTATION) & 0x7F) * 0.049087387
        )
        vel = Vec2(
            float((rng.rand_tagged(RngCallerStatic.CREATURE_APPLY_DAMAGE_SHOCK_BURST_VEL_X) & 0x7F) - 0x40),
            float((rng.rand_tagged(RngCallerStatic.CREATURE_APPLY_DAMAGE_SHOCK_BURST_VEL_Y) & 0x7F) - 0x40),
        )
        scale_step = (
            float(rng.rand_tagged(RngCallerStatic.CREATURE_APPLY_DAMAGE_SHOCK_BURST_SCALE_STEP) % 140) * 0.01 + 0.3
        )
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


def resolve_native_death_sfx(
    creature: CreatureState,
    *,
    rng: CrandLike,
    preserve_bugs: bool = False,
) -> tuple[SfxId, ...]:
    """Resolve the native `creature_apply_damage` death sound, if this path owns one."""
    if (creature.flags & CreatureFlags.RANGED_ATTACK_SHOCK) != 0:
        return ()
    roll = rng.rand_tagged(RngCallerStatic.CREATURE_APPLY_DAMAGE_DEATH_SFX)
    if creature.type_id == CreatureTypeId.TROOPER:
        if preserve_bugs:
            return (_TROOPER_DEATH_SFX_PRESERVE_BUGS[roll & 3],)
        return (_TROOPER_DEATH_SFX[roll % len(_TROOPER_DEATH_SFX)],)
    options = _CREATURE_DEATH_SFX.get(creature.type_id)
    if options is None:
        return ()
    return (options[roll & 3],)


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
    preserve_bugs: bool = False,
) -> bool:
    """Apply damage to a creature, returning True if the hit killed it.

    This is a partial port of `creature_apply_damage` (FUN_004207c0).

    Notes:
    - Death side-effects (handle_death, then shock burst / death SFX) are handled
      by the caller in native order.
    - `damage_type` is a native integer category; call sites must supply it.
    """

    creature.last_hit_owner = owner
    creature.hit_flash_timer = f32(0.2)

    ctx = _CreatureDamageCtx(
        creature=creature,
        damage=f32(damage_amount),
        damage_type=int(damage_type),
        impulse=Vec2(f32(impulse.x), f32(impulse.y)),
        owner=owner,
        dt=f32(dt),
        players=players,
        rng=rng,
        preserve_bugs=bool(preserve_bugs),
    )

    for step in _CREATURE_DAMAGE_GLOBAL_PRE_STEPS.get(ctx.damage_type, ()):
        step(ctx)

    for step in _CREATURE_DAMAGE_PRE_STEPS.get(ctx.damage_type, ()):
        step(ctx)
    if ctx.damage_type == CreatureDamageType.BULLET:
        _damage_type1_heading_jitter(ctx)

    if creature.hp <= 0.0:
        if ctx.dt > 0.0:
            creature.lifecycle_stage = x87_pc24_sub(
                creature.lifecycle_stage,
                x87_pc24_mul(ctx.dt, 15.0),
            )
        return True

    for step in _CREATURE_DAMAGE_ALIVE_STEPS.get(ctx.damage_type, ()):
        step(ctx)

    creature.hp = x87_pc24_sub(creature.hp, ctx.damage)
    creature.vel = Vec2(
        x87_pc24_sub(creature.vel.x, ctx.impulse.x),
        x87_pc24_sub(creature.vel.y, ctx.impulse.y),
    )

    if creature.hp <= 0.0:
        if ctx.dt > 0.0:
            creature.lifecycle_stage = x87_pc24_sub(creature.lifecycle_stage, ctx.dt)
        else:
            creature.lifecycle_stage = x87_pc24_sub(creature.lifecycle_stage, f32(0.001))
        creature.vel = Vec2(
            x87_pc24_sub(creature.vel.x, x87_pc24_mul(ctx.impulse.x, 2.0)),
            x87_pc24_sub(creature.vel.y, x87_pc24_mul(ctx.impulse.y, 2.0)),
        )
        return True

    return False


def creature_apply_damage_with_lethal_followup(
    creature: CreatureState,
    *,
    creature_index: int,
    damage_amount: float,
    damage_type: int,
    impulse: Vec2,
    owner: OwnerRef,
    dt: float,
    players: list[PlayerState],
    rng: CrandLike,
    preserve_bugs: bool = False,
    effects: EffectPool | None = None,
    detail_preset: int = 5,
    creature_damage_runtime: CreatureDamageRuntime,
) -> bool:
    """Apply damage and run a required lethal follow-up exactly on death transition.

    This helper keeps lethal bookkeeping adjacent to damage application so runtime
    call sites cannot accidentally skip death handling side effects.
    """

    # Native gates the lethal branch purely on entry health; a creature whose
    # death was already handled with hp still positive (shrinkifier shrink-death,
    # energizer eat) re-enters the full lethal follow-up on a later killing hit.
    death_start_needed = float(creature.hp) > 0.0
    killed = creature_apply_damage(
        creature,
        damage_amount=float(damage_amount),
        damage_type=int(damage_type),
        impulse=impulse,
        owner=owner,
        dt=float(dt),
        players=players,
        rng=rng,
        preserve_bugs=bool(preserve_bugs),
    )
    if killed and death_start_needed:

        def _resolve_death_sfx() -> tuple[SfxId, ...]:
            # Native lethal order: `creature_handle_death` runs first, then either the
            # shock-burst rand loop (`flags & 0x10`) or the death-SFX rand draw.
            _damage_lethal_ranged_shock_burst(
                creature=creature,
                rng=rng,
                effects=effects,
                detail_preset=int(detail_preset),
            )
            return resolve_native_death_sfx(creature, rng=rng, preserve_bugs=preserve_bugs)

        creature_damage_runtime.on_creature_lethal(int(creature_index), _resolve_death_sfx)
        return True
    return False
