from __future__ import annotations

"""Fire Bullets feature hooks for deterministic presentation output."""

import msgspec

from grim.geom import Vec2
from grim.rand import CrandLike

from ..effects import FxQueue
from ..math_parity import f32
from ..projectiles.types import ProjectileHit
from ..rng_caller_static import RngCallerStatic
from .apply_context import BonusApplyCtx, bonus_apply_seconds


class LargeHitDecalRuntime(msgspec.Struct):
    def spawn_freeze_shard(self, pos: Vec2, angle: float) -> None:
        _ = pos, angle


def apply_fire_bullets(ctx: BonusApplyCtx) -> None:
    ctx.register_if_inactive()
    ctx.player.fire_bullets_timer = float(
        f32(float(ctx.player.fire_bullets_timer) + bonus_apply_seconds(ctx) * float(ctx.economist_multiplier)),
    )
    ctx.player.weapon_reset_latch = 0
    ctx.player.weapon.shot_cooldown = 0.0
    ctx.player.weapon.reload_timer = 0.0
    ctx.player.weapon.ammo = float(ctx.player.weapon.clip_size)


def queue_large_hit_decal_streak(
    *,
    hit: ProjectileHit,
    base_angle: float,
    fx_queue: FxQueue,
    rng: CrandLike,
    freeze_origin: Vec2 | None = None,
    runtime: LargeHitDecalRuntime | None = None,
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
        if runtime is not None and freeze_origin is not None:
            freeze_pos = freeze_origin + direction * (dist * 20.0)
            freeze_angle = (
                float(base_angle)
                + float(rng.rand_tagged(RngCallerStatic.PROJECTILE_UPDATE_LARGE_STREAK_FREEZE_ANGLE) % 100) * 0.01
            )
            runtime.spawn_freeze_shard(freeze_pos, freeze_angle)
        fx_queue.add_random(
            pos=hit.target + direction * (dist * 20.0),
            rng=rng,
        )
