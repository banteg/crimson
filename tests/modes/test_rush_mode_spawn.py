from __future__ import annotations

import math

from crimson.creatures.runtime import CreaturePool, CreatureState
from crimson.creatures.spawn import (
    CreatureFlags,
    CreatureTypeId,
    creature_spawn,
    tick_rush_mode_spawns,
)
from crimson.math_parity import f32
from crimson.rng_caller_static import RngCallerStatic
from grim.color import RGBA
from grim.geom import Vec2
from grim.rand import Crand, CrandLike, RecordingCrand
from tests.support.helpers import assert_float_close


def _tick(rng: CrandLike, cooldown: float, *, survival_elapsed_ms: int = 0) -> tuple[float, list[CreatureState]]:
    pool = CreaturePool()
    cooldown = tick_rush_mode_spawns(pool, cooldown, 0.0, rng, player_count=1, survival_elapsed_ms=survival_elapsed_ms)
    return cooldown, [creature for creature in pool.entries if creature.active]


def test_tick_rush_mode_spawns_no_trigger() -> None:
    rng = Crand(1)
    pool = CreaturePool()
    cooldown = tick_rush_mode_spawns(pool, 100.0, 16.0, rng, player_count=1, survival_elapsed_ms=0)

    assert_float_close(cooldown, 84.0)
    assert not any(creature.active for creature in pool.entries)
    assert rng.state == 1


def test_rush_spawn_stats_round_each_native_x87_operation() -> None:
    def spawn(survival_elapsed_ms: int) -> CreatureState:
        pool = CreaturePool()
        idx = creature_spawn(pool, Vec2(), RGBA(), CreatureTypeId.ALIEN, Crand(1), survival_elapsed_ms=survival_elapsed_ms)
        return pool.entries[idx]

    health_case = spawn(474)
    assert health_case.hp == 10.04740047454834  # native health scale at 0x0046f310
    assert health_case.max_hp == health_case.hp
    assert spawn(237).move_speed == 2.5023701190948486
    assert spawn(3792).size == 47.03792190551758


def test_tick_rush_mode_spawns_triggers_two_creatures() -> None:
    rng = Crand(1)
    cooldown, spawns = _tick(rng, -1.0)

    assert_float_close(cooldown, 249.0)
    alien, spider = spawns

    expected_tint = RGBA(
        0.3000083565711975,  # native PC24 fmul/fadd: 0x3e999ab2
        1.0,  # clamp01(0.3 + 10000.0)
        float(f32(math.sin(float(f32(f32(1.0) * f32(1e-4)))) + f32(0.3))),
        1.0,
    )
    assert alien.type_id == CreatureTypeId.ALIEN
    assert alien.ai_mode == 8
    assert alien.flags == CreatureFlags(0)
    assert alien.pos == Vec2(1088.0, 768.0)
    assert alien.hp == 10.0
    assert alien.max_hp == 10.0
    assert alien.move_speed == 2.5
    assert alien.reward_value == 144.0
    assert alien.size == 47.0
    assert alien.tint == expected_tint

    assert spider.type_id == CreatureTypeId.SPIDER_SP1
    assert spider.ai_mode == 8
    assert spider.flags == CreatureFlags.AI7_LINK_TIMER
    assert spider.pos == Vec2(-64.0, 512.0)
    assert spider.hp == 10.0
    assert spider.max_hp == 10.0
    assert spider.move_speed == 3.5
    assert spider.reward_value == 144.0
    assert spider.size == 47.0
    assert spider.tint == expected_tint

    assert rng.state == 0x3D6C1037


def test_tick_rush_mode_spawns_uses_native_upward_rounded_sine_scale() -> None:
    _, spawns = _tick(Crand(1), -1.0, survival_elapsed_ms=63)

    assert spawns[0].tint.b == 0.30639997124671936


def test_tick_rush_mode_spawns_uses_exact_native_callers() -> None:
    rng = RecordingCrand(Crand(0x1234))

    _tick(rng, -1.0)

    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
        RngCallerStatic.CREATURE_SPAWN_HEADING,
        RngCallerStatic.CREATURE_SPAWN_REWARD,
        RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
        RngCallerStatic.CREATURE_SPAWN_HEADING,
        RngCallerStatic.CREATURE_SPAWN_REWARD,
    ]


def test_tick_rush_mode_spawns_loops_when_cooldown_is_very_negative() -> None:
    rng = Crand(1)
    cooldown, spawns = _tick(rng, -501.0)

    assert_float_close(cooldown, 249.0)
    assert [c.type_id for c in spawns] == [CreatureTypeId.ALIEN, CreatureTypeId.SPIDER_SP1] * 3
    assert rng.state == 0xAEA69ED3
