from __future__ import annotations

import math

from crimson.creatures.runtime import CreaturePool, CreatureState
from crimson.creatures.spawn import CreatureFlags, CreatureTypeId, creature_spawn
from crimson.math_parity import f32
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.mode_updates import RushSpawnState, rush_mode_update
from crimson.weapons import WeaponId
from grim.color import RGBA
from grim.geom import Vec2
from grim.rand import Crand, CrandLike, RecordingCrand
from tests.support.builders.session import make_world
from tests.support.helpers import assert_float_close


def _tick(rng: CrandLike, cooldown: float, *, survival_elapsed_ms: int = 0) -> tuple[float, list[CreatureState]]:
    world = make_world()
    world.state.rng = rng
    spawn = RushSpawnState(spawn_cooldown_ms=cooldown)
    rush_mode_update(world, spawn, elapsed_ms=float(survival_elapsed_ms), dt_ms=0.0)
    return spawn.spawn_cooldown_ms, [creature for creature in world.creatures.entries if creature.active]


def test_rush_mode_update_forces_assault_rifles_without_spawning_before_the_cooldown() -> None:
    world = make_world(player_count=2)
    world.state.rng = Crand(1)
    spawn = RushSpawnState(spawn_cooldown_ms=100.0)

    rush_mode_update(world, spawn, elapsed_ms=0.0, dt_ms=16.0)

    assert_float_close(spawn.spawn_cooldown_ms, 68.0)
    assert [(player.weapon.weapon_id, player.weapon.ammo) for player in world.players] == [
        (WeaponId.ASSAULT_RIFLE, 30.0),
        (WeaponId.ASSAULT_RIFLE, 30.0),
    ]
    assert not any(creature.active for creature in world.creatures.entries)
    assert world.state.rng.state == 1


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


def test_rush_mode_update_triggers_two_creatures() -> None:
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


def test_rush_mode_update_uses_native_upward_rounded_sine_scale() -> None:
    _, spawns = _tick(Crand(1), -1.0, survival_elapsed_ms=63)

    assert spawns[0].tint.b == 0.30639997124671936


def test_rush_mode_update_uses_exact_native_callers() -> None:
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


def test_rush_mode_update_loops_when_cooldown_is_very_negative() -> None:
    rng = Crand(1)
    cooldown, spawns = _tick(rng, -501.0)

    assert_float_close(cooldown, 249.0)
    assert [c.type_id for c in spawns] == [CreatureTypeId.ALIEN, CreatureTypeId.SPIDER_SP1] * 3
    assert rng.state == 0xAEA69ED3
