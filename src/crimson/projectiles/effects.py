from __future__ import annotations

from collections.abc import MutableSequence

from grim.color import RGBA
from grim.geom import Vec2
from grim.rand import CrandLike
from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest

from ..effects import EffectPool
from ..effects_atlas import EffectId
from ..math_parity import (
    NATIVE_TAU,
    f32,
    x87_pc24_add,
    x87_pc24_cos_mul,
    x87_pc24_mul,
    x87_pc24_mul_chain,
    x87_pc24_sin_mul,
    x87_pc24_sub,
)
from ..rng_caller_static import RngCallerStatic
from .types import ProjectileTemplateId


def _spawn_shrinkifier_hit_effects(
    effects: EffectPool,
    *,
    pos: Vec2,
    rng: CrandLike,
    detail_preset: int,
) -> None:
    """Port of `effect_spawn_shrinkifier_hit` (0x0042f080); `scale` and `rotation_step` are inherited."""

    template = effects.template
    template.flags = 0x19
    template.color = RGBA(0.3, 0.6, 0.9, 1.0)
    template.age = 0.0
    template.lifetime = 0.3
    template.half_width = 36.0
    template.half_height = 36.0
    template.rotation = 0.0
    template.vel = Vec2()
    template.scale_step = -4.0
    effects.spawn(EffectId.RING, pos, detail_preset)

    template.flags = 0x1D
    template.color = RGBA(0.4, 0.5, 1.0, 0.5)
    template.age = 0.0
    template.lifetime = 0.3
    template.half_width = 32.0
    template.half_height = 32.0

    count = 4
    if detail_preset < 3:
        count //= 2

    for _ in range(count):
        template.rotation = x87_pc24_mul(
            float(rng.rand_tagged(RngCallerStatic.SHRINKIFIER_HIT_ROTATION) & 0x7F), f32(0.0490873866),
        )
        template.vel = Vec2(
            x87_pc24_mul(float((rng.rand_tagged(RngCallerStatic.SHRINKIFIER_HIT_VEL_X) & 0x7F) - 0x40), f32(1.4)),
            x87_pc24_mul(float((rng.rand_tagged(RngCallerStatic.SHRINKIFIER_HIT_VEL_Y) & 0x7F) - 0x40), f32(1.4)),
        )
        template.scale_step = x87_pc24_add(
            x87_pc24_mul(float(rng.rand_tagged(RngCallerStatic.SHRINKIFIER_HIT_SCALE_STEP) % 100), f32(0.01)), f32(0.1),
        )
        effects.spawn(EffectId.BURST, pos, detail_preset)


def _effect_spawn_ion_hit_core(
    effects: EffectPool,
    *,
    pos: Vec2,
    scale_step: float,
    lifetime: float,
    detail_preset: int,
) -> None:
    """Port of `effect_spawn_ion_hit_core`; `scale` and `rotation_step` are inherited."""

    template = effects.template
    template.flags = 0x19
    template.color = RGBA(0.6, 0.6, 0.9, 1.0)
    template.lifetime = x87_pc24_mul(f32(lifetime), f32(0.8))
    template.scale_step = x87_pc24_mul(f32(scale_step), 45.0)
    template.age = 0.0
    template.half_width = 4.0
    template.half_height = 4.0
    template.rotation = 0.0
    template.vel = Vec2()
    effects.spawn(EffectId.RING, pos, detail_preset)


def _effect_spawn_ion_hit_sparks(
    effects: EffectPool,
    *,
    pos: Vec2,
    scale: float,
    rng: CrandLike,
    detail_preset: int,
) -> None:
    """Port of `effect_spawn_ion_hit_sparks`; `scale` and `rotation_step` are inherited."""

    scale = x87_pc24_mul(f32(scale), f32(0.8))
    template = effects.template
    template.flags = 0x1D
    template.color = RGBA(0.4, 0.5, 1.0, 0.5)
    lifetime = x87_pc24_mul(scale, f32(0.7))
    template.lifetime = lifetime
    template.age = 0.0
    if lifetime > f32(1.1):
        template.lifetime = 1.1

    template.half_width = x87_pc24_mul(scale, 32.0)
    template.half_height = x87_pc24_mul(scale, 32.0)

    # `__ftol(scale * 5.0f)`, halved at low detail.
    count = int(x87_pc24_mul(scale, 5.0))
    if detail_preset < 3:
        count //= 2
    if count <= 0:
        return

    for _ in range(count):
        template.rotation = x87_pc24_mul(
            float(rng.rand_tagged(RngCallerStatic.ION_HIT_SPARK_ROTATION) & 0x7F), f32(0.0490873866),
        )
        template.vel = Vec2(
            x87_pc24_mul_chain(float((rng.rand_tagged(RngCallerStatic.ION_HIT_SPARK_VEL_X) & 0x7F) - 0x40), scale, f32(1.4)),
            x87_pc24_mul_chain(float((rng.rand_tagged(RngCallerStatic.ION_HIT_SPARK_VEL_Y) & 0x7F) - 0x40), scale, f32(1.4)),
        )
        template.scale_step = x87_pc24_mul(
            x87_pc24_add(
                x87_pc24_mul(float(rng.rand_tagged(RngCallerStatic.ION_HIT_SPARK_SCALE_STEP) % 100), f32(0.01)), f32(0.1),
            ),
            scale,
        )
        effects.spawn(EffectId.BURST, pos, detail_preset)


def _spawn_ion_hit_effects(
    effects: EffectPool,
    sfx_queue: MutableSequence[SfxRequest],
    *,
    type_id: ProjectileTemplateId,
    pos: Vec2,
    rng: CrandLike,
    detail_preset: int,
) -> None:
    """The ion branches of the `projectile_update` hit: a core then sparks, plus the cannon's shockwave."""

    match type_id:
        case ProjectileTemplateId.ION_MINIGUN:
            _effect_spawn_ion_hit_core(effects, pos=pos, scale_step=1.5, lifetime=0.1, detail_preset=detail_preset)
            _effect_spawn_ion_hit_sparks(effects, pos=pos, scale=0.8, rng=rng, detail_preset=detail_preset)
        case ProjectileTemplateId.ION_RIFLE:
            _effect_spawn_ion_hit_core(effects, pos=pos, scale_step=1.2, lifetime=0.4, detail_preset=detail_preset)
            _effect_spawn_ion_hit_sparks(effects, pos=pos, scale=1.2, rng=rng, detail_preset=detail_preset)
        case ProjectileTemplateId.ION_CANNON:
            _effect_spawn_ion_hit_core(effects, pos=pos, scale_step=1.0, lifetime=1.0, detail_preset=detail_preset)
            _effect_spawn_ion_hit_sparks(effects, pos=pos, scale=2.2, rng=rng, detail_preset=detail_preset)
            sfx_queue.append(SfxRequest(SfxId.SHOCKWAVE, pos))


def _effect_spawn_plasma_hit_core(
    effects: EffectPool,
    *,
    pos: Vec2,
    scale_step: float,
    lifetime: float,
    detail_preset: int,
) -> None:
    """Port of `effect_spawn_plasma_hit_core`; `scale` and `rotation_step` are inherited."""

    template = effects.template
    template.flags = 0x19
    template.color = RGBA(0.9, 0.6, 0.3, 1.0)
    template.age = 0.1
    template.lifetime = lifetime
    template.scale_step = x87_pc24_mul(f32(scale_step), 45.0)
    template.half_width = 4.0
    template.half_height = 4.0
    template.rotation = 0.0
    template.vel = Vec2()
    effects.spawn(EffectId.RING, pos, detail_preset)


def _spawn_plasma_cannon_hit_effects(
    effects: EffectPool,
    sfx_queue: MutableSequence[SfxRequest],
    *,
    pos: Vec2,
    detail_preset: int,
) -> None:
    """The Plasma Cannon hit extras of `projectile_update`: two sounds, then two plasma cores."""

    sfx_queue.append(SfxRequest(SfxId.EXPLOSION_MEDIUM, pos))
    sfx_queue.append(SfxRequest(SfxId.SHOCKWAVE, pos))
    _effect_spawn_plasma_hit_core(effects, pos=pos, scale_step=1.5, lifetime=1.0, detail_preset=detail_preset)
    _effect_spawn_plasma_hit_core(effects, pos=pos, scale_step=1.0, lifetime=1.0, detail_preset=detail_preset)


def _spawn_splitter_hit_effects(
    effects: EffectPool,
    *,
    pos: Vec2,
    rng: CrandLike,
    detail_preset: int,
) -> None:
    """Port of `effect_spawn_splitter_hit_burst(pos, 26.0, 3)`; `scale` and `rotation_step` are inherited."""

    template = effects.template
    template.flags = 0x19
    template.color = RGBA(1.0, 0.9, 0.1, 1.0)
    template.half_width = 4.0
    template.half_height = 4.0
    template.rotation = 0.0
    template.vel = Vec2()
    template.scale_step = 55.0

    for _ in range(3):
        angle = x87_pc24_mul(
            float(rng.rand_tagged(RngCallerStatic.SPLITTER_HIT_ANGLE) & 0x1FF) * 0.001953125, NATIVE_TAU,
        )
        distance = float(rng.rand_tagged(RngCallerStatic.SPLITTER_HIT_RADIUS) % 26)
        spawn_pos = Vec2(
            x87_pc24_add(x87_pc24_cos_mul(angle, distance), pos.x),
            x87_pc24_add(x87_pc24_sin_mul(angle, distance), pos.y),
        )
        # Native negates the integer before conversion, so a zero draw gives +0.0.
        template.age = x87_pc24_mul(float(-(rng.rand_tagged(RngCallerStatic.SPLITTER_HIT_AGE) & 0xFF)), f32(0.0012))
        template.lifetime = x87_pc24_sub(f32(0.1), template.age)
        effects.spawn(EffectId.BURST, spawn_pos, detail_preset)


__all__ = [
    "_spawn_ion_hit_effects",
    "_spawn_plasma_cannon_hit_effects",
    "_spawn_shrinkifier_hit_effects",
    "_spawn_splitter_hit_effects",
]
