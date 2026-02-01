from __future__ import annotations

import pytest

from crimson.creatures.anim import creature_anim_advance_phase, creature_anim_select_frame, creature_corpse_frame_for_type
from crimson.creatures.spawn import CreatureFlags


def test_creature_anim_advance_phase_long_strip_matches_formula() -> None:
    # rate=1.2, move_speed=2.0, dt=1/60, size=50:
    # step = 1.2 * 2.0 * (1/60) * (30/50) * 1.0 * 25 = 0.6
    phase, step = creature_anim_advance_phase(
        0.0,
        anim_rate=1.2,
        move_speed=2.0,
        dt=1.0 / 60.0,
        size=50.0,
        local_scale=1.0,
        flags=CreatureFlags(0),
        ai_mode=0,
    )
    assert step == pytest.approx(0.6, abs=1e-6)
    assert phase == pytest.approx(0.6, abs=1e-6)


def test_creature_anim_advance_phase_ping_pong_uses_22_multiplier() -> None:
    # Same inputs as above, but ping-pong uses 22 instead of 25:
    # step = 1.2 * 2.0 * (1/60) * (30/50) * 1.0 * 22 = 0.528
    phase, step = creature_anim_advance_phase(
        0.0,
        anim_rate=1.2,
        move_speed=2.0,
        dt=1.0 / 60.0,
        size=50.0,
        local_scale=1.0,
        flags=CreatureFlags.ANIM_PING_PONG,
        ai_mode=0,
    )
    assert step == pytest.approx(0.528, abs=1e-6)
    assert phase == pytest.approx(0.528, abs=1e-6)


def test_creature_anim_select_frame_ping_pong_basic() -> None:
    flags = CreatureFlags.ANIM_PING_PONG
    base = 0x20
    # idx=0 -> base+0x10+0 = 0x30
    frame, mirror_applied, mode = creature_anim_select_frame(0.0, base_frame=base, mirror_long=False, flags=flags)
    assert (frame, mirror_applied, mode) == (0x30, False, "ping-pong")

    # idx=7 -> base+0x10+7 = 0x37
    frame, mirror_applied, mode = creature_anim_select_frame(7.0, base_frame=base, mirror_long=False, flags=flags)
    assert (frame, mirror_applied, mode) == (0x37, False, "ping-pong")

    # idx=8 -> mirrored to 7 -> 0x37
    frame, mirror_applied, mode = creature_anim_select_frame(8.0, base_frame=base, mirror_long=False, flags=flags)
    assert (frame, mirror_applied, mode) == (0x37, False, "ping-pong")

    # idx=15 -> mirrored to 0 -> 0x30
    frame, mirror_applied, mode = creature_anim_select_frame(15.0, base_frame=base, mirror_long=False, flags=flags)
    assert (frame, mirror_applied, mode) == (0x30, False, "ping-pong")


def test_creature_anim_select_frame_long_strip_mirror_flag_is_index_mirror() -> None:
    # When the per-type mirror flag is set, long strip turns into a ping-pong of 16 frames:
    # phase 16 -> ftol(16.0 + 0.5) == 16, then mirrored to 31 - 16 == 15.
    frame, mirror_applied, mode = creature_anim_select_frame(
        16.0, base_frame=0x10, mirror_long=True, flags=CreatureFlags(0)
    )
    assert (frame, mirror_applied, mode) == (15, True, "long")


def test_creature_corpse_frame_ping_pong_fallback_uses_native_special_entry() -> None:
    # Native uses a special creature_type_table entry (effect id 7) for ping-pong strip corpses.
    assert creature_corpse_frame_for_type(7) == 6
