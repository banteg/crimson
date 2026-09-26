from __future__ import annotations

import math

import msgspec

from grim.color import RGBA
from grim.geom import Vec2
from grim.math import clamp01

from ..creatures.spawn import CreatureTypeId
from ..math_parity import f32, x87_pc24_add, x87_pc24_cos_mul, x87_pc24_mul


class TypoSpawnCall(msgspec.Struct, frozen=True):
    pos: Vec2
    type_id: CreatureTypeId
    tint_rgba: RGBA


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

        # `typo_gameplay_update_and_render` (0x00445af4..0x00445c15): float
        # literals at PC24; `fsin`/`fcos` stay wide until the next op rounds.
        tint_t = float(elapsed_ms + 1)
        tint_r = clamp01(x87_pc24_add(x87_pc24_mul(tint_t, f32(0.00000833333343)), f32(0.3)))
        tint_g = clamp01(x87_pc24_add(x87_pc24_mul(tint_t, 10000.0), f32(0.3)))
        tint_b = clamp01(x87_pc24_add(math.sin(x87_pc24_mul(tint_t, f32(0.000100000005))), f32(0.3)))
        tint = RGBA(tint_r, tint_g, tint_b, 1.0)

        t = x87_pc24_mul(float(elapsed_ms), f32(0.001))
        y = x87_pc24_add(x87_pc24_cos_mul(t, 256.0), x87_pc24_mul(float(world_height), 0.5))

        spawns.append(
            TypoSpawnCall(
                pos=Vec2(x87_pc24_add(float(world_width), 64.0), y),
                type_id=CreatureTypeId.SPIDER_SP2,
                tint_rgba=tint,
            ),
        )
        spawns.append(
            TypoSpawnCall(
                pos=Vec2(-64.0, y),
                type_id=CreatureTypeId.ALIEN,
                tint_rgba=tint,
            ),
        )

    return cooldown, spawns
