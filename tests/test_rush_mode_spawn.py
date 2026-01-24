from __future__ import annotations

import math

import pytest

from crimson.crand import Crand
from crimson.creatures.spawn import CreatureFlags, CreatureTypeId, tick_rush_mode_spawns


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

    assert cooldown == pytest.approx(84.0, abs=1e-9)
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

    assert cooldown == pytest.approx(249.0, abs=1e-9)
    assert len(spawns) == 2

    alien, spider = spawns

    assert alien.type_id == CreatureTypeId.ALIEN
    assert alien.ai_mode == 8
    assert alien.flags == CreatureFlags(0)
    assert (alien.pos_x, alien.pos_y) == (pytest.approx(1088.0, abs=1e-9), pytest.approx(768.0, abs=1e-9))
    assert alien.health == pytest.approx(10.0, abs=1e-9)
    assert alien.max_health == pytest.approx(10.0, abs=1e-9)
    assert alien.move_speed == pytest.approx(2.5, abs=1e-9)
    assert alien.reward_value == pytest.approx(144.0, abs=1e-9)
    assert alien.size == pytest.approx(47.0, abs=1e-9)
    expected_tint_r = 0.3 + 1.0 / 120000.0
    expected_tint_g = 1.0  # clamp01(0.3 + 10000.0)
    expected_tint_b = 0.3 + math.sin(1e-4)
    assert alien.tint == pytest.approx((expected_tint_r, expected_tint_g, expected_tint_b, 1.0), abs=1e-9)

    assert spider.type_id == CreatureTypeId.SPIDER_SP1
    assert spider.ai_mode == 8
    assert (spider.flags & CreatureFlags.AI7_LINK_TIMER) != 0
    assert (spider.pos_x, spider.pos_y) == (pytest.approx(-64.0, abs=1e-9), pytest.approx(512.0, abs=1e-9))
    assert spider.health == pytest.approx(10.0, abs=1e-9)
    assert spider.max_health == pytest.approx(10.0, abs=1e-9)
    assert spider.move_speed == pytest.approx(3.5, abs=1e-9)
    assert spider.reward_value == pytest.approx(144.0, abs=1e-9)
    assert spider.size == pytest.approx(47.0, abs=1e-9)
    assert spider.tint == pytest.approx((expected_tint_r, expected_tint_g, expected_tint_b, 1.0), abs=1e-9)

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

    assert cooldown == pytest.approx(249.0, abs=1e-9)
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
