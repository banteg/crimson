"""Large-hit decal streaks queued for Gauss and Fire Bullets impacts."""

from __future__ import annotations

from grim.geom import Vec2
from grim.rand import CrandLike

from ..effects import EffectPool, FxQueue
from ..math_parity import f32, x87_pc24_add, x87_pc24_mul
from ..projectiles.types import ProjectileHit
from ..rng_caller_static import RngCallerStatic


def queue_large_hit_decal_streak(
    *,
    hit: ProjectileHit,
    base_angle: float,
    fx_queue: FxQueue,
    rng: CrandLike,
    freeze_effects: EffectPool | None,
    detail_preset: int,
) -> None:
    """Queue the large decal streak used by Fire Bullets impact hits."""
    direction = Vec2.from_angle(base_angle)
    for _ in range(6):
        dist = float(rng.rand_tagged(RngCallerStatic.PROJECTILE_UPDATE_LARGE_STREAK_DIST) % 100) * 0.1
        if dist > 4.0:
            dist = float(rng.rand_tagged(RngCallerStatic.PROJECTILE_UPDATE_LARGE_STREAK_DIST_GT4) % 90 + 10) * 0.1
        if dist > 7.0:
            dist = float(rng.rand_tagged(RngCallerStatic.PROJECTILE_UPDATE_LARGE_STREAK_DIST_GT7) % 80 + 20) * 0.1
        # Native `projectile_update` consumes one unconditional draw per loop
        # before the freeze branch (`crt_rand` @ 0x0042184c).
        rng.rand_tagged(RngCallerStatic.PROJECTILE_UPDATE_LARGE_STREAK_BURN)
        if freeze_effects is not None:
            # Native `angle - 1.5707964f + (float)(crt_rand() % 100) * 0.01f`, single precision.
            freeze_angle = x87_pc24_add(
                base_angle,
                x87_pc24_mul(
                    float(rng.rand_tagged(RngCallerStatic.PROJECTILE_UPDATE_LARGE_STREAK_FREEZE_ANGLE) % 100), f32(0.01),
                ),
            )
            freeze_effects.spawn_freeze_shard(
                pos=hit.hit + direction * (dist * 20.0),
                angle=freeze_angle,
                rng=rng,
                detail_preset=detail_preset,
            )
        fx_queue.add_random(
            pos=hit.target + direction * (dist * 20.0),
            rng=rng,
        )
