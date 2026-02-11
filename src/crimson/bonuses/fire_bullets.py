from __future__ import annotations

"""Fire Bullets feature hooks for deterministic presentation output."""

from typing import Callable

from grim.geom import Vec2

from ..effects import FxQueue
from ..projectiles import ProjectileHit


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
