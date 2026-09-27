from __future__ import annotations

from crimson.creatures.runtime import CREATURE_LIFECYCLE_ALIVE
from crimson.creatures.spawn import CreatureFlags, CreatureTypeId
from crimson.effects import FxQueue
from crimson.math_parity import f32, x87_pc24_hypot, x87_pc24_mul, x87_pc24_sub
from crimson.perks import PerkId
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import step_creatures
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_radioactive_tick_deals_damage_and_spawns_fx() -> None:
    dt = 0.2
    world = make_world()
    state = world.state
    state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    player = world.players[0]
    player.pos = Vec2()
    state.perks[int(PerkId.RADIOACTIVE)] = 1

    creature = world.creatures.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(46.0, 0.0)
    creature.hp = 50.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.collision_timer = 0.1

    step_runtime = step_creatures(world, dt, fx_queue=FxQueue())

    # Radioactive pulse evaluates after movement/clamp in the live-creature body.
    dist_after_move = x87_pc24_hypot(
        x87_pc24_sub(creature.pos.x, player.pos.x),
        x87_pc24_sub(creature.pos.y, player.pos.y),
    )
    expected_damage = x87_pc24_mul(
        x87_pc24_sub(f32(100.0), dist_after_move),
        f32(0.3),
    )
    assert_float_close(creature.collision_timer, 0.5)
    assert_float_close(creature.hp, x87_pc24_sub(f32(50.0), expected_damage))
    assert step_runtime.fx_queue.count == 1


def test_radioactive_kill_awards_base_xp_and_bypasses_death_multipliers() -> None:
    dt = 0.2
    world = make_world()
    state = world.state
    state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    state.bonuses.double_experience = 5.0

    player = world.players[0]
    player.pos = Vec2()
    player.experience = 100
    state.perks[int(PerkId.RADIOACTIVE)] = 1
    state.perks[int(PerkId.BLOODY_MESS_QUICK_LEARNER)] = 1

    creature = world.creatures.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(46.0, 0.0)
    creature.hp = 5.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.reward_value = 12.7
    creature.collision_timer = 0.1

    step_runtime = step_creatures(world, dt, fx_queue=FxQueue())

    assert player.experience == 112
    assert not step_runtime.deaths
    assert creature.hp < 0.0
    assert_float_close(
        creature.lifecycle_stage,
        x87_pc24_sub(CREATURE_LIFECYCLE_ALIVE, float(dt)),
    )
    assert step_runtime.fx_queue.count == 1


def test_radioactive_sets_hp_to_one_for_type_id_one_creatures() -> None:
    dt = 0.2
    world = make_world()
    state = world.state
    state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    player = world.players[0]
    player.pos = Vec2()
    player.experience = 100
    state.perks[int(PerkId.RADIOACTIVE)] = 1

    creature = world.creatures.entries[0]
    creature.active = True
    creature.type_id = CreatureTypeId.LIZARD
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(46.0, 0.0)
    creature.hp = 5.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.reward_value = 12.7
    creature.collision_timer = 0.1

    step_runtime = step_creatures(world, dt, fx_queue=FxQueue())

    assert player.experience == 100
    assert not step_runtime.deaths
    assert_float_close(creature.hp, 1.0)
    assert_float_close(creature.lifecycle_stage, CREATURE_LIFECYCLE_ALIVE)
    assert_float_close(creature.collision_timer, 0.5)
    assert step_runtime.fx_queue.count == 1


def test_radioactive_pulse_measures_distance_to_target_player() -> None:
    dt = 0.2
    world = make_world(player_count=2)
    state = world.state
    state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    # The creature targets player slot one and is only in range of that selected target.
    player1, player2 = world.players
    player1.pos = Vec2(900.0, 900.0)
    state.perks[int(PerkId.RADIOACTIVE)] = 1
    player2.pos = Vec2()

    creature = world.creatures.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(46.0, 0.0)
    creature.hp = 50.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.collision_timer = 0.1
    creature.target_player = 1

    step_creatures(world, dt)

    assert creature.hp < 50.0
    # Kill XP is credited to player 1 (native writes the global _player_experience).
    assert player2.experience == 0


def test_radioactive_pulse_requires_living_creature() -> None:
    dt = 0.2
    world = make_world()
    state = world.state
    state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    player = world.players[0]
    player.pos = Vec2()
    state.perks[int(PerkId.RADIOACTIVE)] = 1

    creature = world.creatures.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(46.0, 0.0)
    creature.hp = -1.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.collision_timer = 0.1
    experience_before = player.experience

    step_creatures(world, dt)

    # Native requires hp > 0 at timer fire: an already-dead creature is not
    # pulsed again (no XP re-award, no collision timer reset).
    assert player.experience == experience_before
    assert creature.collision_timer != 0.5
