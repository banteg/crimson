from __future__ import annotations

from crimson.creatures.runtime import CREATURE_LIFECYCLE_ALIVE, CreatureState
from crimson.creatures.spawn import CreatureFlags
from crimson.math_parity import NATIVE_HALF_PI, f32
from crimson.rng_caller_static import RngCallerStatic
from grim.geom import Vec2
from tests.support.factories import kill_creature, world_with_creature
from tests.support.helpers import ScriptedCrand


def test_split_on_death_spawns_two_smaller_children() -> None:
    rng = ScriptedCrand([0x111, 0x123, 0x222, 0x456], fallback=ScriptedCrand.Fallback.ZERO)
    parent = CreatureState(
        active=True,
        flags=CreatureFlags.SPLIT_ON_DEATH,
        pos=Vec2(100.0, 200.0),
        heading=3.0,
        target_heading=-0.75,
        hp=0.0,
        max_hp=400.0,
        reward_value=90.0,
        size=40.0,
        move_speed=2.0,
        contact_damage=10.0,
    )
    world = world_with_creature(parent, rng=rng)
    # Kill drops are out of scope here; the guard skips them before any draw.
    world.state.bonus_spawn_guard = True
    pool = world.creatures

    kill_creature(world)

    child1 = pool.entries[1]
    child2 = pool.entries[2]
    assert child1.active and child2.active
    assert child1.lifecycle_stage == CREATURE_LIFECYCLE_ALIVE
    assert child2.lifecycle_stage == CREATURE_LIFECYCLE_ALIVE
    assert child1.phase_seed == 0x123 & 0xFF
    assert child2.phase_seed == 0x456 & 0xFF
    assert child1.heading == f32(parent.heading - NATIVE_HALF_PI)
    assert child2.heading == f32(parent.heading + NATIVE_HALF_PI)
    assert child1.target_heading == parent.target_heading
    assert child2.target_heading == parent.target_heading
    assert child1.hp == f32(parent.max_hp * f32(0.25))
    assert child2.hp == f32(parent.max_hp * f32(0.25))
    assert child1.size == f32(parent.size - f32(8.0))
    assert child2.size == f32(parent.size - f32(8.0))
    assert child1.move_speed == f32(parent.move_speed + f32(0.1))
    assert child2.move_speed == f32(parent.move_speed + f32(0.1))
    assert child1.contact_damage == f32(parent.contact_damage * f32(0.7))
    assert child2.contact_damage == f32(parent.contact_damage * f32(0.7))
    # Native draws two rands per child: the alloc-slot phase seed (immediately
    # overwritten by the parent struct copy) and the final phase seed.
    assert [record.caller for record in rng.records_since()[:4]] == [
        RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
        RngCallerStatic.CREATURE_HANDLE_DEATH_SPLIT_CHILD_1_PHASE_SEED,
        RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
        RngCallerStatic.CREATURE_HANDLE_DEATH_SPLIT_CHILD_2_PHASE_SEED,
    ]
    # Native multiplies by the f32 literal 0.6666667.
    assert child1.reward_value == f32(parent.reward_value * f32(0.6666667))
    assert child2.reward_value == f32(parent.reward_value * f32(0.6666667))
