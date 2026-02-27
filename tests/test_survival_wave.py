from __future__ import annotations

from crimson.creatures.spawn import CreatureTypeId, tick_survival_wave_spawns
from grim.rand import Crand
from tests.helpers import assert_float_close


def test_tick_survival_wave_spawns_no_trigger() -> None:
    rng = Crand(123)
    cooldown, spawns = tick_survival_wave_spawns(
        100.0,
        16.0,
        rng,
        player_count=2,
        survival_elapsed_ms=0.0,
        player_experience=0,
        terrain_width=1024,
        terrain_height=1024,
    )

    assert_float_close(cooldown, 68.0)
    assert spawns == ()
    assert rng.state == 123


def test_tick_survival_wave_spawns_triggers_single_spawn() -> None:
    rng = Crand(1)
    cooldown, spawns = tick_survival_wave_spawns(
        -1.0,
        0.0,
        rng,
        player_count=1,
        survival_elapsed_ms=0.0,
        player_experience=0,
        terrain_width=1024,
        terrain_height=1024,
    )

    assert_float_close(cooldown, 499.0)
    assert len(spawns) == 1
    c = spawns[0]

    assert_float_close(c.pos.x, 35.0)
    assert_float_close(c.pos.y, 1064.0)
    assert c.type_id == CreatureTypeId.ALIEN
    assert_float_close(c.health, 85.0)
    assert_float_close(c.reward_value, 336.0)
    assert rng.state == 0xA6E9C9A6


def test_tick_survival_wave_spawns_extra_spawns_when_interval_is_negative() -> None:
    rng = Crand(1)
    cooldown, spawns = tick_survival_wave_spawns(
        -1.0,
        0.0,
        rng,
        player_count=1,
        survival_elapsed_ms=905400.0,  # 500 - (elapsed/0x708) == -3
        player_experience=0,
        terrain_width=1024,
        terrain_height=1024,
    )

    assert_float_close(cooldown, 0.0)
    assert len(spawns) == 3
    for spawn, (expected_x, expected_y) in zip(spawns, ((35.0, 1064.0), (1064.0, 947.0), (-40.0, 435.0))):
        assert_float_close(spawn.pos.x, expected_x)
        assert_float_close(spawn.pos.y, expected_y)
    assert [c.type_id for c in spawns] == [
        CreatureTypeId.ALIEN,
        CreatureTypeId.ALIEN,
        CreatureTypeId.SPIDER_SP1,
    ]
    assert rng.state == 0xBB25E9C6


def test_tick_survival_wave_spawns_loops_until_cooldown_is_non_negative() -> None:
    rng = Crand(1)
    cooldown, spawns = tick_survival_wave_spawns(
        -2.0,
        0.0,
        rng,
        player_count=1,
        survival_elapsed_ms=905400.0,  # interval branch resolves to 1ms after extras
        player_experience=0,
        terrain_width=1024,
        terrain_height=1024,
    )

    # Native loops while cooldown < 0, so -2 with +1 interval runs two iterations.
    assert_float_close(cooldown, 0.0)
    assert len(spawns) == 6
