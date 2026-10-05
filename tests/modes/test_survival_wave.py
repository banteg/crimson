from __future__ import annotations

import pytest

from crimson.creatures.runtime import CreatureState
from crimson.creatures.spawn import CreatureTypeId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.mode_updates import SurvivalSpawnState, survival_update
from grim.rand import Crand, CrandLike
from tests.support.builders.session import make_world
from tests.support.helpers import ScriptedCrand, assert_float_close


def _tick(
    rng: CrandLike,
    cooldown: float,
    dt_ms: float,
    *,
    player_count: int = 1,
    run_elapsed_ms: float = 0.0,
) -> tuple[float, list[CreatureState]]:
    world = make_world(player_count=player_count)
    world.state.rng = rng
    spawn = SurvivalSpawnState(spawn_cooldown_ms=cooldown)
    survival_update(world, spawn, elapsed_ms=run_elapsed_ms, dt_ms=dt_ms)
    return spawn.spawn_cooldown_ms, [creature for creature in world.creatures.entries if creature.active]


# Past 15 minutes (500 - 905400 / 1800 == -3) each pass spawns two extras before the main creature.
_EXTRA_SPAWNS_ELAPSED_MS = 905400.0


@pytest.mark.parametrize(
    ("elapsed_ms", "edge_caller", "coord_callers"),
    [
        (
            0.0,
            RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_EDGE,
            (
                RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_TOP_X,
                RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_BOTTOM_X,
                RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_LEFT_Y,
                RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_RIGHT_Y,
            ),
        ),
        (
            _EXTRA_SPAWNS_ELAPSED_MS,
            RngCallerStatic.SURVIVAL_UPDATE_EXTRA_SPAWN_EDGE,
            (
                RngCallerStatic.SURVIVAL_UPDATE_EXTRA_SPAWN_TOP_X,
                RngCallerStatic.SURVIVAL_UPDATE_EXTRA_SPAWN_BOTTOM_X,
                RngCallerStatic.SURVIVAL_UPDATE_EXTRA_SPAWN_LEFT_Y,
                RngCallerStatic.SURVIVAL_UPDATE_EXTRA_SPAWN_RIGHT_Y,
            ),
        ),
    ],
)
@pytest.mark.parametrize(
    ("edge_draw", "coord_draw", "expected_pos"),
    [
        (0, 12, (12.0, -40.0)),
        (1, 13, (13.0, 1064.0)),
        (2, 14, (-40.0, 14.0)),
        (3, 15, (1064.0, 15.0)),
    ],
)
def test_wave_spawn_edges_use_exact_native_callers(
    elapsed_ms: float,
    edge_caller: RngCallerStatic,
    coord_callers: tuple[RngCallerStatic, ...],
    edge_draw: int,
    coord_draw: int,
    expected_pos: tuple[float, float],
) -> None:
    rng = ScriptedCrand([edge_draw, coord_draw], fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    _, spawns = _tick(rng, -1.0, 0.0, run_elapsed_ms=elapsed_ms)

    assert_float_close(spawns[0].pos.x, expected_pos[0])
    assert_float_close(spawns[0].pos.y, expected_pos[1])
    assert [record.caller for record in rng.records[:2]] == [edge_caller, coord_callers[edge_draw]]


def test_survival_wave_spawns_no_trigger() -> None:
    rng = Crand(123)
    cooldown, spawns = _tick(rng, 100.0, 16.0, player_count=2)

    assert_float_close(cooldown, 68.0)
    assert spawns == []
    assert rng.state == 123


def test_survival_wave_spawns_triggers_single_spawn() -> None:
    rng = Crand(1)
    cooldown, spawns = _tick(rng, -1.0, 0.0)

    assert_float_close(cooldown, 499.0)
    assert len(spawns) == 1
    c = spawns[0]

    assert_float_close(c.pos.x, 35.0)
    assert_float_close(c.pos.y, 1064.0)
    assert c.type_id == CreatureTypeId.ALIEN
    assert_float_close(c.hp, 85.0)
    assert_float_close(c.reward_value, 336.0)
    assert rng.state == 0xA6E9C9A6


def test_survival_wave_spawns_extra_spawns_when_interval_is_negative() -> None:
    rng = Crand(1)
    cooldown, spawns = _tick(rng, -1.0, 0.0, run_elapsed_ms=_EXTRA_SPAWNS_ELAPSED_MS)

    assert_float_close(cooldown, 0.0)
    assert len(spawns) == 3
    for spawn, (expected_x, expected_y) in zip(spawns, ((35.0, 1064.0), (1064.0, 947.0), (-40.0, 435.0)), strict=True):
        assert_float_close(spawn.pos.x, expected_x)
        assert_float_close(spawn.pos.y, expected_y)
    assert [c.type_id for c in spawns] == [
        CreatureTypeId.ALIEN,
        CreatureTypeId.ALIEN,
        CreatureTypeId.SPIDER_SP1,
    ]
    assert rng.state == 0xBB25E9C6


def test_survival_wave_spawns_uses_distinct_extra_and_main_position_callers() -> None:
    rng = ScriptedCrand([0], fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    _tick(rng, -1.0, 0.0, run_elapsed_ms=_EXTRA_SPAWNS_ELAPSED_MS)

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


def test_survival_wave_spawns_loops_until_cooldown_is_non_negative() -> None:
    rng = Crand(1)
    cooldown, spawns = _tick(rng, -2.0, 0.0, run_elapsed_ms=_EXTRA_SPAWNS_ELAPSED_MS)  # interval branch resolves to 1ms after extras

    # Native loops while cooldown < 0, so -2 with +1 interval runs two iterations.
    assert_float_close(cooldown, 0.0)
    assert len(spawns) == 6
