from __future__ import annotations

import math

from crimson.creatures.spawn import CreatureFlags, CreatureTypeId, tick_rush_mode_spawns
from crimson.math_parity import f32
from grim.rand import Crand
from tests.support.helpers import assert_float_close


def test_tick_rush_mode_spawns_no_trigger() -> None:
    rng = Crand(1)
    cooldown, spawns = tick_rush_mode_spawns(
        100.0,
        16.0,
        rng,
        player_count=1,
        survival_elapsed_ms=0,
        terrain_width=1024.0,
        terrain_height=1024.0,
    )

    assert_float_close(cooldown, 84.0)
    assert spawns == ()
    assert rng.state == 1


def test_tick_rush_mode_spawns_triggers_two_creatures() -> None:
    rng = Crand(1)
    cooldown, spawns = tick_rush_mode_spawns(
        -1.0,
        0.0,
        rng,
        player_count=1,
        survival_elapsed_ms=0,
        terrain_width=1024.0,
        terrain_height=1024.0,
    )

    assert_float_close(cooldown, 249.0)
    assert len(spawns) == 2

    alien, spider = spawns

    assert alien.type_id == CreatureTypeId.ALIEN
    assert alien.ai_mode == 8
    assert alien.flags == CreatureFlags(0)
    assert_float_close(alien.pos.x, 1088.0)
    assert_float_close(alien.pos.y, 768.0)
    assert_float_close(alien.health, 10.0)
    assert_float_close(alien.max_health, 10.0)
    assert_float_close(alien.move_speed, 2.5)
    assert_float_close(alien.reward_value, 144.0)
    assert_float_close(alien.size, 47.0)
    expected_tint_r = float(f32(f32(1.0) * f32(1.0 / 120000.0) + 0.3))
    expected_tint_g = 1.0  # clamp01(0.3 + 10000.0)
    expected_tint_b = float(f32(math.sin(float(f32(f32(1.0) * f32(1e-4)))) + 0.3))
    assert alien.tint is not None
    assert_float_close(alien.tint[0], expected_tint_r)
    assert_float_close(alien.tint[1], expected_tint_g)
    assert_float_close(alien.tint[2], expected_tint_b)
    assert_float_close(alien.tint[3], 1.0)

    assert spider.type_id == CreatureTypeId.SPIDER_SP1
    assert spider.ai_mode == 8
    assert (spider.flags & CreatureFlags.AI7_LINK_TIMER) != 0
    assert_float_close(spider.pos.x, -64.0)
    assert_float_close(spider.pos.y, 512.0)
    assert_float_close(spider.health, 10.0)
    assert_float_close(spider.max_health, 10.0)
    assert_float_close(spider.move_speed, 3.5)
    assert_float_close(spider.reward_value, 144.0)
    assert_float_close(spider.size, 47.0)
    assert spider.tint is not None
    assert_float_close(spider.tint[0], expected_tint_r)
    assert_float_close(spider.tint[1], expected_tint_g)
    assert_float_close(spider.tint[2], expected_tint_b)
    assert_float_close(spider.tint[3], 1.0)

    assert rng.state == 0x3D6C1037


def test_tick_rush_mode_spawns_loops_when_cooldown_is_very_negative() -> None:
    rng = Crand(1)
    cooldown, spawns = tick_rush_mode_spawns(
        -501.0,
        0.0,
        rng,
        player_count=1,
        survival_elapsed_ms=0,
        terrain_width=1024.0,
        terrain_height=1024.0,
    )

    assert_float_close(cooldown, 249.0)
    assert len(spawns) == 6
    assert [c.type_id for c in spawns] == [
        CreatureTypeId.ALIEN,
        CreatureTypeId.SPIDER_SP1,
        CreatureTypeId.ALIEN,
        CreatureTypeId.SPIDER_SP1,
        CreatureTypeId.ALIEN,
        CreatureTypeId.SPIDER_SP1,
    ]
    assert rng.state == 0xAEA69ED3
