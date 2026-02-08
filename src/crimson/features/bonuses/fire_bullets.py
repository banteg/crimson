from __future__ import annotations

"""Fire Bullets feature hooks for deterministic presentation output."""

from typing import Callable

from grim.geom import Vec2

from ...effects import FxQueue
from ...projectiles import ProjectileHit


def queue_large_hit_decal_streak(
    *,
    hit: ProjectileHit,
    base_angle: float,
    fx_queue: FxQueue,
    rand: Callable[[], int],
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
        fx_queue.add_random(
            pos=hit.target + direction * (dist * 20.0),
            rand=rand,
        )
