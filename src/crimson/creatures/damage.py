from __future__ import annotations

from collections.abc import Callable

from grim.color import RGBA
from grim.geom import Vec2
from grim.rand import CrandLike
from grim.sfx_map import SfxId

from ..effects import EffectPool
from ..effects_atlas import EffectId
from ..math_parity import NATIVE_HALF_PI, f32, x87_pc24_add, x87_pc24_div, x87_pc24_mul, x87_pc24_sub
from ..owner_ref import OwnerRef
from ..perks import PerkId
from ..rng_caller_static import RngCallerStatic
from ..sim.state_types import PerkCounts, PlayerState
from .damage_types import CreatureDamageType
from .runtime import CreatureState
from .spawn import CreatureFlags, CreatureTypeId

# The callback must handle death synchronously, then invoke the supplied
# follow-up before returning: native impulse/SFX/shock RNG runs in that order.
type CreatureLethalHandler = Callable[[int, Callable[[], tuple[SfxId, ...]]], None]

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


def creature_death_sfx_for_slot(type_id: CreatureTypeId, sound_slot: int) -> SfxId | None:
    options = _TROOPER_DEATH_SFX if type_id == CreatureTypeId.TROOPER else _CREATURE_DEATH_SFX.get(type_id)
    slot = int(sound_slot)
    if options is None or not (0 <= slot < len(options)):
        return None
    return options[slot]


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
        rotation = x87_pc24_mul(
            float(rng.rand_tagged(RngCallerStatic.CREATURE_APPLY_DAMAGE_SHOCK_BURST_ROTATION) & 0x7F),
            f32(0.049087387),
        )
        vel = Vec2(
            float((rng.rand_tagged(RngCallerStatic.CREATURE_APPLY_DAMAGE_SHOCK_BURST_VEL_X) & 0x7F) - 0x40),
            float((rng.rand_tagged(RngCallerStatic.CREATURE_APPLY_DAMAGE_SHOCK_BURST_VEL_Y) & 0x7F) - 0x40),
        )
        scale_step = x87_pc24_add(
            x87_pc24_mul(
                float(rng.rand_tagged(RngCallerStatic.CREATURE_APPLY_DAMAGE_SHOCK_BURST_SCALE_STEP) % 140),
                f32(0.01),
            ),
            f32(0.3),
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


def creature_apply_damage(
    creature: CreatureState,
    *,
    damage_amount: float,
    damage_type: int,
    impulse: Vec2,
    owner: OwnerRef,
    dt: float,
    players: list[PlayerState],
    perks: PerkCounts,
    rng: CrandLike,
) -> bool:
    """Apply damage to a creature (`creature_apply_damage`), returning True if the hit killed it.

    Notes:
    - Death side-effects (handle_death, doubled lethal impulse, then shock burst /
      death SFX) are handled by the caller in native order.
    - `damage_type` is a native integer category; call sites must supply it.
    """

    creature.last_hit_owner = owner
    creature.hit_flash_timer = f32(0.2)
    damage = f32(damage_amount)
    dt = f32(dt)

    if damage_type == CreatureDamageType.BULLET:
        if PerkId.URANIUM_FILLED_BULLETS in perks:
            damage = x87_pc24_add(damage, damage)
        if PerkId.LIVING_FORTRESS in perks:
            for player in players:
                timer = float(player.living_fortress_timer)
                if float(player.health) > 0.0 and timer > 0.0:
                    damage = x87_pc24_mul(damage, x87_pc24_add(x87_pc24_mul(timer, f32(0.05)), 1.0))
        if PerkId.BARREL_GREASER in perks:
            damage = x87_pc24_mul(damage, f32(1.4))
        if PerkId.DOCTOR in perks:
            damage = x87_pc24_mul(damage, f32(1.2))
    elif damage_type == CreatureDamageType.ION and PerkId.ION_GUN_MASTER in perks:
        damage = x87_pc24_mul(damage, f32(1.2))

    if damage_type == CreatureDamageType.BULLET and (creature.flags & CreatureFlags.ANIM_PING_PONG) == 0:
        jitter = x87_pc24_mul(
            float((rng.rand_tagged(RngCallerStatic.CREATURE_APPLY_DAMAGE_HEADING_JITTER) & 0x7F) - 0x40),
            f32(0.002),
        )
        turn = x87_pc24_div(jitter, x87_pc24_mul(max(1e-6, float(creature.size)), f32(0.025)))
        # Native clamps against the f32 literal 1.5707964 and stores the sum f32.
        creature.heading = x87_pc24_add(min(float(NATIVE_HALF_PI), turn), creature.heading)

    if creature.hp <= 0.0:
        if dt > 0.0:
            creature.lifecycle_stage = x87_pc24_sub(creature.lifecycle_stage, x87_pc24_mul(dt, 15.0))
        return True

    if damage_type == CreatureDamageType.FIRE and PerkId.PYROMANIAC in perks:
        damage = x87_pc24_mul(damage, f32(1.5))
        rng.rand_tagged(RngCallerStatic.CREATURE_APPLY_DAMAGE_PYROMANIAC)

    creature.hp = x87_pc24_sub(creature.hp, damage)
    creature.vel = Vec2(
        x87_pc24_sub(creature.vel.x, f32(impulse.x)),
        x87_pc24_sub(creature.vel.y, f32(impulse.y)),
    )

    if creature.hp <= 0.0:
        if dt > 0.0:
            creature.lifecycle_stage = x87_pc24_sub(creature.lifecycle_stage, dt)
        else:
            creature.lifecycle_stage = x87_pc24_sub(creature.lifecycle_stage, f32(0.001))
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
    perks: PerkCounts,
    rng: CrandLike,
    preserve_bugs: bool = False,
    effects: EffectPool | None = None,
    detail_preset: int = 5,
    on_lethal: CreatureLethalHandler,
) -> bool:
    """Apply damage and run a required lethal follow-up exactly on death transition.

    This helper keeps lethal bookkeeping adjacent to damage application so runtime
    call sites cannot accidentally skip death handling side effects.
    """

    # Native gates the lethal branch purely on entry health; a creature whose
    # death was already handled with hp still positive (shrinkifier shrink-death,
    # energizer eat) re-enters the full lethal follow-up on a later killing hit.
    death_start_needed = float(creature.hp) > 0.0
    native_impulse = Vec2(f32(impulse.x), f32(impulse.y))
    killed = creature_apply_damage(
        creature,
        damage_amount=float(damage_amount),
        damage_type=int(damage_type),
        impulse=native_impulse,
        owner=owner,
        dt=float(dt),
        players=players,
        perks=perks,
        rng=rng,
    )
    if killed and death_start_needed:

        def _resolve_damage_followup() -> tuple[SfxId, ...]:
            # Native lethal order: `creature_handle_death` runs first, the current
            # source-slot record receives a second 2x impulse, then either the
            # shock-burst rand loop (`flags & 0x10`) or the death-SFX rand draw.
            creature.vel = Vec2(
                x87_pc24_sub(creature.vel.x, x87_pc24_mul(native_impulse.x, 2.0)),
                x87_pc24_sub(creature.vel.y, x87_pc24_mul(native_impulse.y, 2.0)),
            )
            _damage_lethal_ranged_shock_burst(
                creature=creature,
                rng=rng,
                effects=effects,
                detail_preset=int(detail_preset),
            )
            return resolve_native_death_sfx(creature, rng=rng, preserve_bugs=preserve_bugs)

        on_lethal(int(creature_index), _resolve_damage_followup)
        return True
    return False
