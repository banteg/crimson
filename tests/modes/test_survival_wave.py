from __future__ import annotations

import pytest

from crimson.creatures.spawn import (
    SURVIVAL_UPDATE_EXTRA_SPAWN_POS_CALLERS,
    SURVIVAL_UPDATE_MAIN_SPAWN_POS_CALLERS,
    CreatureTypeId,
    SurvivalSpawnPosCallers,
    rand_survival_spawn_pos,
    tick_survival_wave_spawns,
)
from crimson.rng_caller_static import RngCallerStatic
from grim.rand import Crand
from tests.support.helpers import ScriptedCrand, assert_float_close


@pytest.mark.parametrize(
    ("callers", "edge_draw", "coord_draw", "expected_pos", "expected_callers"),
    [
        (
            SURVIVAL_UPDATE_EXTRA_SPAWN_POS_CALLERS,
            0,
            12,
            (12.0, -40.0),
            [
                RngCallerStatic.SURVIVAL_UPDATE_EXTRA_SPAWN_EDGE,
                RngCallerStatic.SURVIVAL_UPDATE_EXTRA_SPAWN_TOP_X,
            ],
        ),
        (
            SURVIVAL_UPDATE_EXTRA_SPAWN_POS_CALLERS,
            1,
            13,
            (13.0, 1064.0),
            [
                RngCallerStatic.SURVIVAL_UPDATE_EXTRA_SPAWN_EDGE,
                RngCallerStatic.SURVIVAL_UPDATE_EXTRA_SPAWN_BOTTOM_X,
            ],
        ),
        (
            SURVIVAL_UPDATE_EXTRA_SPAWN_POS_CALLERS,
            2,
            14,
            (-40.0, 14.0),
            [
                RngCallerStatic.SURVIVAL_UPDATE_EXTRA_SPAWN_EDGE,
                RngCallerStatic.SURVIVAL_UPDATE_EXTRA_SPAWN_LEFT_Y,
            ],
        ),
        (
            SURVIVAL_UPDATE_EXTRA_SPAWN_POS_CALLERS,
            3,
            15,
            (1064.0, 15.0),
            [
                RngCallerStatic.SURVIVAL_UPDATE_EXTRA_SPAWN_EDGE,
                RngCallerStatic.SURVIVAL_UPDATE_EXTRA_SPAWN_RIGHT_Y,
            ],
        ),
        (
            SURVIVAL_UPDATE_MAIN_SPAWN_POS_CALLERS,
            0,
            12,
            (12.0, -40.0),
            [
                RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_EDGE,
                RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_TOP_X,
            ],
        ),
        (
            SURVIVAL_UPDATE_MAIN_SPAWN_POS_CALLERS,
            1,
            13,
            (13.0, 1064.0),
            [
                RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_EDGE,
                RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_BOTTOM_X,
            ],
        ),
        (
            SURVIVAL_UPDATE_MAIN_SPAWN_POS_CALLERS,
            2,
            14,
            (-40.0, 14.0),
            [
                RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_EDGE,
                RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_LEFT_Y,
            ],
        ),
        (
            SURVIVAL_UPDATE_MAIN_SPAWN_POS_CALLERS,
            3,
            15,
            (1064.0, 15.0),
            [
                RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_EDGE,
                RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_RIGHT_Y,
            ],
        ),
    ],
)
def test_rand_survival_spawn_pos_uses_exact_native_callers(
    callers: SurvivalSpawnPosCallers,
    edge_draw: int,
    coord_draw: int,
    expected_pos: tuple[float, float],
    expected_callers: list[RngCallerStatic],
) -> None:
    rng = ScriptedCrand([edge_draw, coord_draw])

    pos = rand_survival_spawn_pos(rng, terrain_width=1024, terrain_height=1024, callers=callers)

    assert_float_close(pos.x, expected_pos[0])
    assert_float_close(pos.y, expected_pos[1])
    assert [record.caller for record in rng.records_since()] == expected_callers


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


def test_tick_survival_wave_spawns_uses_distinct_extra_and_main_position_callers() -> None:
    rng = ScriptedCrand([0], fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    tick_survival_wave_spawns(
        -1.0,
        0.0,
        rng,
        player_count=1,
        survival_elapsed_ms=905400.0,
        player_experience=0,
        terrain_width=1024,
        terrain_height=1024,
    )

    position_callers = [
        record.caller
        for record in rng.records_since()
        if record.caller in {
            RngCallerStatic.SURVIVAL_UPDATE_EXTRA_SPAWN_EDGE,
            RngCallerStatic.SURVIVAL_UPDATE_EXTRA_SPAWN_TOP_X,
            RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_EDGE,
            RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_TOP_X,
        }
    ]

    assert position_callers == [
        RngCallerStatic.SURVIVAL_UPDATE_EXTRA_SPAWN_EDGE,
        RngCallerStatic.SURVIVAL_UPDATE_EXTRA_SPAWN_TOP_X,
        RngCallerStatic.SURVIVAL_UPDATE_EXTRA_SPAWN_EDGE,
        RngCallerStatic.SURVIVAL_UPDATE_EXTRA_SPAWN_TOP_X,
        RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_EDGE,
        RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_TOP_X,
    ]


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
