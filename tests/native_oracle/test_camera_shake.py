"""`camera_update` (0x00409500) shake timer vs `camera_shake_update`.

Plays whole Nuke shakes (`camera_shake_pulses = 0x14`, `camera_shake_timer =
0.2f`) frame by frame with varied frame times and the Reflex Boost latch, and
compares the f32 timer, the pulse count, the offsets and the CRT `rand()` state
after every frame.
"""

from __future__ import annotations

import random

from crimson.bonuses.nuke import NUKE_CAMERA_SHAKE_PULSES, NUKE_CAMERA_SHAKE_TIMER
from crimson.camera import camera_shake_update
from crimson.math_parity import f32
from crimson.sim.gameplay_state import GameplayState
from grim.rand import CrtRand

from ._support import Mismatch, compare_fields, mismatch_report

_FRAME_DTS = (f32(1.0 / 60.0), f32(0.016), f32(0.017), f32(1.0 / 144.0), f32(0.033))


def test_camera_shake_matches_native(oracle) -> None:
    pristine = oracle.snapshot()
    offset = oracle.resolve("camera_shake_offset")
    rng = random.Random(0x409500)
    mismatches: list[Mismatch] = []
    cases = frames = 0
    for _ in range(60):
        cases += 1
        seed = rng.getrandbits(32)
        time_scale_active = rng.random() < 0.3
        oracle.restore(pristine)
        oracle.rand_state = seed
        oracle.write_u8("time_scale_active", int(time_scale_active))
        oracle.write_u32("camera_shake_pulses", NUKE_CAMERA_SHAKE_PULSES)
        oracle.write_f32("camera_shake_timer", NUKE_CAMERA_SHAKE_TIMER)
        state = GameplayState(rng=CrtRand(seed))
        state.time_scale_active = time_scale_active
        state.camera_shake_pulses = NUKE_CAMERA_SHAKE_PULSES
        state.camera_shake_timer = NUKE_CAMERA_SHAKE_TIMER
        while state.camera_shake_timer > 0.0:
            frames += 1
            dt = rng.choice(_FRAME_DTS) if rng.random() < 0.8 else f32(rng.uniform(0.001, 0.05))
            oracle.write_f32("frame_dt", dt)
            oracle.call("camera_update")
            camera_shake_update(state, dt)

            case = f"seed=0x{seed:08x} time_scale={int(time_scale_active)} frame={frames} dt={dt!r}"
            native = {
                "timer": oracle.read_f32("camera_shake_timer"),
                "pulses": oracle.read_i32("camera_shake_pulses"),
                "offset_x": oracle.read_f32(offset),
                "offset_y": oracle.read_f32(offset + 4),
            }
            python = {
                "timer": state.camera_shake_timer,
                "pulses": state.camera_shake_pulses,
                "offset_x": state.camera_shake_offset.x,
                "offset_y": state.camera_shake_offset.y,
            }
            mismatches += compare_fields(case, native, python, address=oracle.resolve("camera_shake_timer"))
            if oracle.rand_state != state.rng.state:
                mismatches.append(Mismatch(case, "rand_state", oracle.rand_state, state.rng.state, 0))
            if mismatches:
                break
    assert frames > 20 * cases
    assert not mismatches, mismatch_report(mismatches, total_cases=frames)
