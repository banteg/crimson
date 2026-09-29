"""`effect_spawn_freeze_shatter` vs `EffectPool.spawn_freeze_shatter`.

The shatter spawns four spinning pieces and then four `effect_spawn_freeze_shard`s, all in single precision
(`angle + (float)i * 1.57079637f`, `(float)(crt_rand() % 612) * 0.01f`, ...). Each case runs the native spawn
from a pristine effect free list and compares the eight entries it pops, in order, with the port's.
"""

from __future__ import annotations

import random

from crimson.effects import EffectPool
from crimson.math_parity import f32
from grim.geom import Vec2
from grim.rand import CrtRand

from ._support import Mismatch, compare_fields, mismatch_report, prepare_gameplay

_ENTRY_NEXT_FREE = 0xB8
_EFFECT_LAYOUT: dict[str, tuple[int, str]] = {
    "pos_x": (0x00, "f"),
    "pos_y": (0x04, "f"),
    "effect_id": (0x08, "B"),
    "vel_x": (0x0C, "f"),
    "vel_y": (0x10, "f"),
    "rotation": (0x14, "f"),
    "scale": (0x18, "f"),
    "half_width": (0x1C, "f"),
    "half_height": (0x20, "f"),
    "age": (0x24, "f"),
    "lifetime": (0x28, "f"),
    "flags": (0x2C, "i"),
    "color_a": (0x3C, "f"),
    "rotation_step": (0x40, "f"),
    "scale_step": (0x44, "f"),
}


def test_freeze_shatter_matches_native(oracle) -> None:
    prepare_gameplay(oracle)
    oracle.write_u32("config_detail_preset", 5)
    pristine = oracle.snapshot()
    pos_arg = oracle.alloc(8)
    rng = random.Random(0x42EE00)
    mismatches: list[Mismatch] = []
    cases = 300
    for case_index in range(cases):
        pos = Vec2(f32(rng.uniform(0.0, 1024.0)), f32(rng.uniform(0.0, 1024.0)))
        angle = f32(rng.uniform(0.0, 6.2831855))
        seed = rng.getrandbits(32)

        oracle.restore(pristine)
        entries = []
        address = oracle.read_u32("effect_free_list_head")
        for _ in range(8):
            entries.append(address)
            address = oracle.read_u32(address + _ENTRY_NEXT_FREE)
        oracle.write_f32(pos_arg, pos.x)
        oracle.write_f32(pos_arg + 4, pos.y)
        oracle.rand_state = seed
        oracle.call("effect_spawn_freeze_shatter", pos_arg, angle)

        crand = CrtRand(seed)
        pool = EffectPool()
        pool.spawn_freeze_shatter(pos=pos, angle=angle, rng=crand, detail_preset=5)
        case = f"case={case_index} angle={angle!r} seed=0x{seed:08x}"
        for index, entry_address in enumerate(entries):
            native = oracle.read_fields(entry_address, _EFFECT_LAYOUT)
            entry = pool.entries[index]
            python = {
                "pos_x": entry.pos.x,
                "pos_y": entry.pos.y,
                "effect_id": entry.effect_id,
                "vel_x": entry.vel.x,
                "vel_y": entry.vel.y,
                "rotation": entry.rotation,
                "scale": entry.scale,
                "half_width": entry.half_width,
                "half_height": entry.half_height,
                "age": entry.age,
                "lifetime": entry.lifetime,
                "flags": entry.flags,
                "color_a": entry.color.a,
                "rotation_step": entry.rotation_step,
                "scale_step": entry.scale_step,
            }
            mismatches += compare_fields(f"{case} effect[{index}]", native, python, address=entry_address)
        if oracle.rand_state != crand.state:
            mismatches.append(Mismatch(case, "rand_state", oracle.rand_state, crand.state, 0))
    assert not mismatches, mismatch_report(mismatches, total_cases=cases)
