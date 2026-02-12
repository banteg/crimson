from __future__ import annotations

import math
from typing import Callable, MutableSequence

from grim.color import RGBA
from grim.geom import Vec2

from ..effects_atlas import EffectId
from .types import ProjectileTypeId, _EffectsLike


def _spawn_shrinkifier_hit_effects(
    effects: _EffectsLike | None,
    *,
    pos: Vec2,
    rng: Callable[[], int],
    detail_preset: int,
) -> None:
    """Port of `effect_spawn_shrinkifier_hit` (0x0042f080)."""

    if effects is None:
        return

    detail = int(detail_preset)

    # Core pulse (effect_id=1).
    effects.spawn(
        effect_id=int(EffectId.RING),
        pos=pos,
        vel=Vec2(),
        rotation=0.0,
        scale=1.0,
        half_width=36.0,
        half_height=36.0,
        age=0.0,
        lifetime=0.3,
        flags=0x19,
        color=RGBA(0.3, 0.6, 0.9, 1.0),
        rotation_step=0.0,
        scale_step=-4.0,
        detail_preset=detail,
    )

    # Debris puffs (effect_id=0), detail-scaled count.
    count = 2 if detail < 3 else 4
    for _ in range(count):
        rotation = float(int(rng()) & 0x7F) * 0.049087387
        velocity = Vec2(
            float((int(rng()) & 0x7F) - 0x40) * 1.4,
            float((int(rng()) & 0x7F) - 0x40) * 1.4,
        )
        scale_step = float(int(rng()) % 100) * 0.01 + 0.1
        effects.spawn(
            effect_id=int(EffectId.BURST),
            pos=pos,
            vel=velocity,
            rotation=rotation,
            scale=1.0,
            half_width=32.0,
            half_height=32.0,
            age=0.0,
            lifetime=0.3,
            flags=0x1D,
            color=RGBA(0.4, 0.5, 1.0, 0.5),
            rotation_step=0.0,
            scale_step=scale_step,
            detail_preset=detail,
        )


def _spawn_ion_hit_effects(
    effects: _EffectsLike | None,
    sfx_queue: MutableSequence[str] | None,
    *,
    type_id: int,
    pos: Vec2,
    rng: Callable[[], int],
    detail_preset: int,
) -> None:
    if effects is None:
        return

    ring_scale = 0.0
    ring_strength = 0.0
    burst_scale = 0.0
    if type_id == int(ProjectileTypeId.ION_MINIGUN):
        ring_scale = 1.5
        ring_strength = 0.1
        burst_scale = 0.8
    elif type_id == int(ProjectileTypeId.ION_RIFLE):
        ring_scale = 1.2
        ring_strength = 0.4
        burst_scale = 1.2
    elif type_id == int(ProjectileTypeId.ION_CANNON):
        ring_scale = 1.0
        ring_strength = 1.0
        burst_scale = 2.2
        if sfx_queue is not None:
            sfx_queue.append("sfx_shockwave")
    else:
        return

    detail = int(detail_preset)

    # Port of `FUN_0042f270(pos, ring_scale, ring_strength)`: ring burst (effect_id=1).
    effects.spawn(
        effect_id=int(EffectId.RING),
        pos=pos,
        vel=Vec2(),
        rotation=0.0,
        scale=1.0,
        half_width=4.0,
        half_height=4.0,
        age=0.0,
        lifetime=float(ring_strength) * 0.8,
        flags=0x19,
        color=RGBA(0.6, 0.6, 0.9, 1.0),
        rotation_step=0.0,
        scale_step=float(ring_scale) * 45.0,
        detail_preset=detail,
    )

    # Port of `FUN_0042f540(pos, burst_scale)`: burst cloud (effect_id=0).
    burst = float(burst_scale) * 0.8
    lifetime = min(burst * 0.7, 1.1)
    half = burst * 32.0
    # Native loop count is `__ftol(scale * 5.0)` after the local `scale *= 0.8`.
    count = int(burst * 5.0)
    if detail < 3:
        count //= 2

    for _ in range(max(0, count)):
        rotation = float(int(rng()) & 0x7F) * 0.049087387
        velocity = Vec2(
            float((int(rng()) & 0x7F) - 0x40) * burst * 1.4,
            float((int(rng()) & 0x7F) - 0x40) * burst * 1.4,
        )
        scale_step = (float(int(rng()) % 100) * 0.01 + 0.1) * burst
        effects.spawn(
            effect_id=int(EffectId.BURST),
            pos=pos,
            vel=velocity,
            rotation=rotation,
            scale=1.0,
            half_width=half,
            half_height=half,
            age=0.0,
            lifetime=float(lifetime),
            flags=0x1D,
            color=RGBA(0.4, 0.5, 1.0, 0.5),
            rotation_step=0.0,
            scale_step=scale_step,
            detail_preset=detail,
        )


def _spawn_plasma_cannon_hit_effects(
    effects: _EffectsLike | None,
    sfx_queue: MutableSequence[str] | None,
    *,
    pos: Vec2,
    detail_preset: int,
) -> None:
    """Port of `projectile_update` Plasma Cannon hit extras.

    Native does:
    - `sfx_play_panned(sfx_explosion_medium)`
    - `sfx_play_panned(sfx_shockwave)`
    - `FUN_0042f330(pos, 1.5, 1.0)`
    - `FUN_0042f330(pos, 1.0, 1.0)`
    """

    if effects is None:
        return

    if sfx_queue is not None:
        sfx_queue.append("sfx_explosion_medium")
        sfx_queue.append("sfx_shockwave")

    detail = int(detail_preset)

    def _spawn_ring(*, scale: float) -> None:
        effects.spawn(
            effect_id=int(EffectId.RING),
            pos=pos,
            vel=Vec2(),
            rotation=0.0,
            scale=1.0,
            half_width=4.0,
            half_height=4.0,
            age=0.1,
            lifetime=1.0,
            flags=0x19,
            color=RGBA(0.9, 0.6, 0.3, 1.0),
            rotation_step=0.0,
            scale_step=float(scale) * 45.0,
            detail_preset=detail,
        )

    _spawn_ring(scale=1.5)
    _spawn_ring(scale=1.0)


def _spawn_splitter_hit_effects(
    effects: _EffectsLike | None,
    *,
    pos: Vec2,
    rng: Callable[[], int],
    detail_preset: int,
) -> None:
    """Port of `FUN_0042f3f0(pos, 26.0, 3)` from the Splitter Gun hit branch."""

    if effects is None:
        return

    detail = int(detail_preset)
    for _ in range(3):
        angle = float(int(rng()) & 0x1FF) * (math.tau / 512.0)
        radius = float(int(rng()) % 26)
        jitter_age = -float(int(rng()) & 0xFF) * 0.0012
        lifetime = 0.1 - jitter_age

        offset = Vec2.from_angle(angle) * radius
        effects.spawn(
            effect_id=int(EffectId.BURST),
            pos=pos + offset,
            vel=Vec2(),
            rotation=0.0,
            scale=1.0,
            half_width=4.0,
            half_height=4.0,
            age=jitter_age,
            lifetime=lifetime,
            flags=0x19,
            color=RGBA(1.0, 0.9, 0.1, 1.0),
            rotation_step=0.0,
            scale_step=55.0,
            detail_preset=detail,
        )


__all__ = [
    "_spawn_ion_hit_effects",
    "_spawn_plasma_cannon_hit_effects",
    "_spawn_shrinkifier_hit_effects",
    "_spawn_splitter_hit_effects",
]
