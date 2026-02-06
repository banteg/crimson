from __future__ import annotations

from dataclasses import dataclass
import math

from grim.geom import Vec2
from grim.math import clamp

from ..creatures.spawn import CreatureTypeId

@dataclass(frozen=True, slots=True)
class TypoSpawnCall:
    pos: Vec2
    type_id: CreatureTypeId
    tint_rgba: tuple[float, float, float, float]


def tick_typo_spawns(
    *,
    elapsed_ms: int,
    spawn_cooldown_ms: int,
    frame_dt_ms: int,
    player_count: int,
    world_width: float,
    world_height: float,
) -> tuple[int, list[TypoSpawnCall]]:
    elapsed_ms = int(elapsed_ms)
    cooldown = int(spawn_cooldown_ms)
    dt_ms = int(frame_dt_ms)
    player_count = max(1, int(player_count))

    cooldown -= dt_ms * player_count

    spawns: list[TypoSpawnCall] = []
    while cooldown < 0:
        cooldown += 3500 - elapsed_ms // 800
        cooldown = max(100, cooldown)

        t = float(elapsed_ms) * 0.001
        y = math.cos(t) * 256.0 + float(world_height) * 0.5

        tint_t = float(elapsed_ms + 1)
        tint_r = clamp(tint_t * 0.0000083333334 + 0.3, 0.0, 1.0)
        tint_g = clamp(tint_t * 10000.0 + 0.3, 0.0, 1.0)
        tint_b = clamp(math.sin(tint_t * 0.0001) + 0.3, 0.0, 1.0)
        tint = (tint_r, tint_g, tint_b, 1.0)

        spawns.append(
            TypoSpawnCall(
                pos=Vec2(float(world_width) + 64.0, y),
                type_id=CreatureTypeId.SPIDER_SP2,
                tint_rgba=tint,
            )
        )
        spawns.append(
            TypoSpawnCall(
                pos=Vec2(-64.0, y),
                type_id=CreatureTypeId.ALIEN,
                tint_rgba=tint,
            )
        )

    return cooldown, spawns
