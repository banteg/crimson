"""Creature animation phase step vs `creature_anim_advance_phase`.

Runs the `creature_update_all` fragment 0x00426e22..0x00426f35: `30.0f / size`,
the PC24 multiply chain with the type's anim rate, move speed, frame time,
move scale and the 25/22 strip multiplier, then the 31/15 wrap.
"""

from __future__ import annotations

import random
import struct

from crimson.creatures.anim import creature_anim_advance_phase
from crimson.creatures.spawn import CreatureAiMode, CreatureFlags
from crimson.math_parity import f32

from ._support import CREATURE_LAYOUT, Mismatch, mismatch_report

_ANIM_START = 0x00426E22
_ANIM_END = 0x00426F35
# `creature_update_all` keeps the frame's move scale at [esp + 0x1c].
_MOVE_SCALE_FRAME_OFFSET = 0x1C
# `creature_type_table` rows are 0x44 bytes.
_TYPE_STRIDE = 0x44
_ANIM_PHASE_OFFSET = 0x94
_FLAG_CHOICES = (
    CreatureFlags(0),
    CreatureFlags.ANIM_PING_PONG,
    CreatureFlags.ANIM_PING_PONG | CreatureFlags.ANIM_LONG_STRIP,
)


def test_creature_anim_phase_matches_native(oracle) -> None:
    creature = oracle.resolve("creature_pool")
    anim_rates = oracle.resolve("creature_type_anim_rate")
    rng = random.Random(0x426E22)
    mismatches: list[Mismatch] = []
    cases = 2000
    for _ in range(cases):
        type_id = rng.randrange(0, 5)
        anim_rate = f32(rng.uniform(0.5, 3.0))
        move_speed = f32(rng.uniform(0.3, 4.8))
        size = f32(rng.uniform(16.0, 90.0))
        move_scale = f32(rng.choice((1.0, rng.uniform(0.2, 1.5))))
        dt = f32(rng.choice((1.0 / 60.0, 0.016, 1.0 / 144.0, rng.uniform(0.001, 0.05))))
        phase = f32(rng.uniform(0.0, 31.0))
        flags = rng.choice(_FLAG_CHOICES)
        ai_mode = rng.choice((CreatureAiMode.ORBIT_PLAYER, CreatureAiMode.HOLD_TIMER))

        oracle.write_f32(anim_rates + type_id * _TYPE_STRIDE, anim_rate)
        oracle.write_u32(creature + CREATURE_LAYOUT["type_id"][0], type_id)
        oracle.write_f32(creature + CREATURE_LAYOUT["move_speed"][0], move_speed)
        oracle.write_f32(creature + CREATURE_LAYOUT["size"][0], size)
        oracle.write_u32(creature + CREATURE_LAYOUT["flags"][0], int(flags))
        oracle.write_u32(creature + CREATURE_LAYOUT["ai_mode"][0], int(ai_mode))
        oracle.write_f32(creature + _ANIM_PHASE_OFFSET, phase)
        oracle.write_f32("frame_dt", dt)
        frame = bytes(_MOVE_SCALE_FRAME_OFFSET) + struct.pack("<f", move_scale)
        oracle.run(_ANIM_START, _ANIM_END, regs={"esi": 0}, frame=frame)
        native = oracle.read_f32(creature + _ANIM_PHASE_OFFSET)

        python, _ = creature_anim_advance_phase(
            phase,
            anim_rate=anim_rate,
            move_speed=move_speed,
            dt=dt,
            size=size,
            local_scale=move_scale,
            flags=flags,
            ai_mode=ai_mode,
        )
        if struct.pack("<f", native) != struct.pack("<f", python) or f32(python) != python:
            case = (
                f"rate={anim_rate!r} speed={move_speed!r} size={size!r} scale={move_scale!r} dt={dt!r} "
                f"phase={phase!r} flags={int(flags):#x} ai_mode={int(ai_mode)}"
            )
            mismatches.append(Mismatch(case, "anim_phase", native, python, creature + _ANIM_PHASE_OFFSET))
    assert not mismatches, mismatch_report(mismatches, total_cases=cases)
