"""Sprite effect loop of `projectile_update` vs `SpriteEffectPool.update`.

Runs the native fragment 0x0042246a..0x004224e8 (position, rotation, alpha
fade and scale of all 0x180 `sprite_effect_pool` entries) frame by frame from
the start alphas the spawners use, and compares every entry after every frame.
"""

from __future__ import annotations

import random

from crimson.effects import SPRITE_EFFECT_POOL_SIZE, SpriteEffectPool
from crimson.math_parity import f32
from grim.color import RGBA
from grim.geom import Vec2
from grim.rand import Crand

from ._support import SPRITE_LAYOUT, SPRITE_STRIDE, Mismatch, compare_fields, mismatch_report, python_sprite

_SPRITE_LOOP_START = 0x0042246A
_SPRITE_LOOP_END = 0x004224E8
_START_ALPHAS = (0.25, 0.37, 0.7, 1.0)
_FRAME_DTS = (f32(1.0 / 60.0), f32(0.016), f32(0.017), f32(1.0 / 144.0))


def test_sprite_effect_update_matches_native(oracle) -> None:
    base = oracle.resolve("sprite_effect_pool")
    rng = random.Random(0x42246A)
    pool = SpriteEffectPool()
    crand = Crand(0)
    for index in range(SPRITE_EFFECT_POOL_SIZE):
        pool.spawn(
            pos=Vec2(rng.uniform(-64.0, 1088.0), rng.uniform(-64.0, 1088.0)),
            vel=Vec2(rng.uniform(-120.0, 120.0), rng.uniform(-120.0, 120.0)),
            scale=rng.uniform(1.0, 32.0),
            color=RGBA(1.0, 1.0, 1.0, rng.choice(_START_ALPHAS)),
            rng=crand,
        )
        entry = pool.entries[index]
        address = base + index * SPRITE_STRIDE
        oracle.write_u8(address, 1)
        for name, value in python_sprite(entry).items():
            if name != "active":
                oracle.write_f32(address + SPRITE_LAYOUT[name][0], value)

    mismatches: list[Mismatch] = []
    frames = 0
    while any(entry.active for entry in pool.entries):
        frames += 1
        dt = rng.choice(_FRAME_DTS)
        oracle.write_f32("frame_dt", dt)
        oracle.run(_SPRITE_LOOP_START, _SPRITE_LOOP_END)
        pool.update(dt)
        for index, entry in enumerate(pool.entries):
            address = base + index * SPRITE_STRIDE
            native = oracle.read_fields(address, SPRITE_LAYOUT)
            if not native["active"] and not entry.active:
                continue
            mismatches += compare_fields(f"frame={frames} dt={dt!r} sprite[{index}]", native, python_sprite(entry), address=address)
        if mismatches:
            break
    assert frames > 30
    assert not mismatches, mismatch_report(mismatches, total_cases=frames)

