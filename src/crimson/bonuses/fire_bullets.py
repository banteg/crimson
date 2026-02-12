from __future__ import annotations

"""Fire Bullets feature hooks for deterministic presentation output."""

from typing import Callable

from grim.geom import Vec2

from ..effects import FxQueue
from ..projectiles import ProjectileHit
from .apply_context import BonusApplyCtx, bonus_apply_seconds


def apply_fire_bullets(ctx: BonusApplyCtx) -> None:
    should_register = float(ctx.player.fire_bullets_timer) <= 0.0
    if ctx.players is not None and len(ctx.players) > 1:
        should_register = (
            float(ctx.players[0].fire_bullets_timer) <= 0.0 and float(ctx.players[1].fire_bullets_timer) <= 0.0
        )
    if should_register:
        ctx.register_player("fire_bullets_timer")
    ctx.player.fire_bullets_timer = float(
        ctx.player.fire_bullets_timer + bonus_apply_seconds(ctx) * ctx.economist_multiplier
    )
    ctx.player.weapon_reset_latch = 0
    ctx.player.shot_cooldown = 0.0
    ctx.player.reload_active = False
    ctx.player.reload_timer = 0.0
    ctx.player.reload_timer_max = 0.0
    ctx.player.ammo = float(ctx.player.clip_size)


def queue_large_hit_decal_streak(
    *,
    hit: ProjectileHit,
    base_angle: float,
    fx_queue: FxQueue,
    rand: Callable[[], int],
    freeze_origin: Vec2 | None = None,
    spawn_freeze_shard: Callable[[Vec2, float], None] | None = None,
) -> None:
    """Queue the large decal streak used by Fire Bullets impact hits."""
    direction = Vec2.from_angle(base_angle)
    for _ in range(6):
        dist = float(int(rand()) % 100) * 0.1
        if dist > 4.0:
            dist = float(int(rand()) % 0x5A + 10) * 0.1
        if dist > 7.0:
            dist = float(int(rand()) % 0x50 + 0x14) * 0.1
        # Native `projectile_update` consumes one unconditional draw per loop
        # before the freeze branch (`crt_rand` @ 0x0042184c).
        rand()
        if spawn_freeze_shard is not None and freeze_origin is not None:
            freeze_pos = freeze_origin + direction * (dist * 20.0)
            freeze_angle = float(base_angle) + float(int(rand()) % 100) * 0.01
            spawn_freeze_shard(freeze_pos, freeze_angle)
        fx_queue.add_random(
            pos=hit.target + direction * (dist * 20.0),
            rand=rand,
        )
