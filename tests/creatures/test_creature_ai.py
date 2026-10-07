from __future__ import annotations

import math
import random
import struct

from crimson.creatures.ai import _orbit_target_f32, creature_ai7_tick_link_timer, creature_ai_update_target
from crimson.creatures.runtime import CreatureState
from crimson.creatures.spawn import CreatureAiMode, CreatureFlags
from crimson.math_parity import NATIVE_PI, f32
from crimson.rng_caller_static import RngCallerStatic
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_ai7_tick_link_timer_negative_to_positive_forces_hold() -> None:
    c = CreatureState(
        pos=Vec2(),
        flags=CreatureFlags.STOP_AND_GO,
        link_index=-10,
        ai_mode=CreatureAiMode.FLANK_PLAYER,
    )
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    creature_ai7_tick_link_timer(c, dt_ms=10, rng=rng)
    assert c.ai_mode == CreatureAiMode.HOLD_TIMER
    assert c.link_index == 500
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.CREATURE_UPDATE_ALL_STOP_AND_GO_HOLD,
    ]


def test_ai7_tick_link_timer_positive_rolls_back_negative() -> None:
    c = CreatureState(pos=Vec2(), flags=CreatureFlags.STOP_AND_GO, link_index=1, ai_mode=CreatureAiMode.HOLD_TIMER)
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    creature_ai7_tick_link_timer(c, dt_ms=1, rng=rng)
    assert c.link_index == -700
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.CREATURE_UPDATE_ALL_STOP_AND_GO_RESET,
    ]


def test_ai_mode_0_orbits_when_close() -> None:
    c = CreatureState(pos=Vec2(), ai_mode=CreatureAiMode.FLANK_PLAYER, phase_seed=0)
    ai = creature_ai_update_target(c, player_pos=Vec2(100.0, 0.0), distance_player_pos=Vec2(100.0, 0.0), creatures=[c], dt=1.0 / 60.0)
    assert_float_close(ai.move_scale, 1.0)
    assert_float_close(c.target.x, 185.0)
    assert_float_close(c.target.y, 0.0)
    assert c.force_target == 0


def test_ai_mode_5_scales_down_near_link() -> None:
    link = CreatureState(pos=Vec2(100.0, 100.0), hp=10.0)
    c = CreatureState(
        pos=Vec2(100.0, 50.0),
        ai_mode=CreatureAiMode.FOLLOW_LINK_TETHERED,
        link_index=0,
        target_offset=Vec2(),
    )
    ai = creature_ai_update_target(c, player_pos=Vec2(), distance_player_pos=Vec2(), creatures=[link, c], dt=1.0 / 60.0)
    assert c.force_target == 0
    assert_float_close(c.target.x, 100.0)
    assert_float_close(c.target.y, 100.0)
    assert_float_close(ai.move_scale, 50.0 * 0.015625)


def test_ai_mode_4_link_death_damage() -> None:
    dead = CreatureState(pos=Vec2(), hp=0.0)
    c = CreatureState(pos=Vec2(10.0, 10.0), ai_mode=CreatureAiMode.FLANK_PLAYER_LINKED, link_index=0)
    ai = creature_ai_update_target(c, player_pos=Vec2(100.0, 0.0), distance_player_pos=Vec2(100.0, 0.0), creatures=[dead, c], dt=1.0 / 60.0)
    assert c.ai_mode == CreatureAiMode.FLANK_PLAYER
    assert ai.link_death_damage == 1000.0


def test_ai_mode_6_orbits_linked_creature() -> None:
    link = CreatureState(pos=Vec2(100.0, 0.0), hp=10.0)
    c = CreatureState(
        pos=Vec2(),
        ai_mode=CreatureAiMode.ORBIT_LINK,
        link_index=0,
        orbit_angle=0.0,
        orbit_radius=10.0,
        heading=0.0,
    )
    ai = creature_ai_update_target(c, player_pos=Vec2(), distance_player_pos=Vec2(), creatures=[link, c], dt=1.0 / 60.0)
    assert ai.link_death_damage is None
    assert c.ai_mode == CreatureAiMode.ORBIT_LINK
    assert c.force_target == 0
    assert_float_close(c.target.x, 110.0)
    assert_float_close(c.target.y, 0.0)


def test_ai_mode_6_keeps_native_orbit_link_x87_staging() -> None:
    link = CreatureState(
        pos=Vec2(49.17198181152344, -107.8695297241211),
        hp=10.0,
    )
    c = CreatureState(
        pos=Vec2(),
        ai_mode=CreatureAiMode.ORBIT_LINK,
        link_index=0,
        orbit_angle=-4.216711521148682,
        orbit_radius=101.34416198730469,
        heading=-2.0916693210601807,
    )

    creature_ai_update_target(c, player_pos=Vec2(), distance_player_pos=Vec2(), creatures=[link, c], dt=1.0 / 60.0)

    assert c.force_target == 0
    assert c.target.x == 150.48397827148438
    assert c.target.y == -110.4227066040039


def test_ai_mode_7_orbit_radius_timer_counts_down() -> None:
    c = CreatureState(pos=Vec2(), ai_mode=CreatureAiMode.HOLD_TIMER, orbit_radius=1.5)
    ai = creature_ai_update_target(c, player_pos=Vec2(100.0, 0.0), distance_player_pos=Vec2(100.0, 0.0), creatures=[c], dt=0.5)
    assert ai.link_death_damage is None
    assert c.ai_mode == CreatureAiMode.HOLD_TIMER
    assert_float_close(c.orbit_radius, 1.0)


def test_ai_targets_and_heading_are_float32_quantized() -> None:
    c = CreatureState(pos=Vec2(0.125, -0.25), ai_mode=CreatureAiMode.FLANK_PLAYER, phase_seed=13)
    creature_ai_update_target(c, player_pos=Vec2(123.5, 456.25), distance_player_pos=Vec2(123.5, 456.25), creatures=[c], dt=1.0 / 60.0)
    assert_float_close(c.target.x, f32(c.target.x))
    assert_float_close(c.target.y, f32(c.target.y))
    assert_float_close(c.target_heading, f32(c.target_heading))


def test_ai_orbit_distance_uses_native_per_operation_f32_rounding() -> None:
    c = CreatureState(
        pos=Vec2(-40.0, 305.0),
        ai_mode=CreatureAiMode.FLANK_PLAYER,
        phase_seed=50,
    )

    creature_ai_update_target(
        c,
        player_pos=Vec2(506.59539794921875, 535.6737060546875),
        distance_player_pos=Vec2(506.59539794921875, 535.6737060546875),
        creatures=[c],
        dt=0.03200000151991844,
    )

    assert c.target.x == 2.31048583984375
    assert c.target.y == 535.673583984375
    assert c.target_heading == 2.9601876735687256


def test_ai_orbit_target_keeps_trig_wide_until_first_multiply() -> None:
    c = CreatureState(
        pos=Vec2(-30.34019660949707, 845.064208984375),
        ai_mode=CreatureAiMode.FLANK_PLAYER,
        phase_seed=316,
    )

    creature_ai_update_target(
        c,
        player_pos=Vec2(364.858154296875, 678.1124267578125),
        distance_player_pos=Vec2(364.858154296875, 678.1124267578125),
        creatures=[c],
        dt=0.04100000113248825,
    )

    assert c.target.x == 69.8948974609375
    assert c.target.y == 463.69183349609375
    assert c.target_heading == 0.25701460242271423


def test_orbit_target_matches_uncached_spills_across_seed_reuse() -> None:
    rng = random.Random(0x17F)
    # All allocated/split seeds, plus non-native seeds to exercise bounded-cache eviction.
    seeds = [*range(384), *range(384), *range(384, 1024), *reversed(range(384))]
    for seed in seeds:
        for scale in (0.85, 0.9, 0.55):
            player_pos = Vec2(rng.uniform(-1024.0, 1024.0), rng.uniform(-1024.0, 1024.0))
            dist = rng.uniform(0.0, 1500.0)
            phase = f32(f32(float(seed) * f32(3.7)) * NATIVE_PI)
            orbit_x = f32(math.cos(phase) * f32(dist))
            orbit_y = f32(math.sin(phase) * f32(dist))
            expected = Vec2(
                f32(f32(orbit_x * f32(scale)) + f32(player_pos.x)),
                f32(f32(orbit_y * f32(scale)) + f32(player_pos.y)),
            )
            actual = _orbit_target_f32(player_pos=player_pos, phase_seed=seed, dist=dist, scale=scale)
            assert struct.pack("<ff", actual.x, actual.y) == struct.pack("<ff", expected.x, expected.y)
