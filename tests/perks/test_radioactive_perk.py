from __future__ import annotations

import pytest

from crimson.creatures.runtime import CREATURE_LIFECYCLE_ALIVE, CreaturePool
from crimson.creatures.spawn import CreatureFlags, CreatureTypeId
from crimson.effects import FxQueue
from crimson.gameplay import GameplayState
from crimson.math_parity import f32, x87_pc24_hypot, x87_pc24_mul, x87_pc24_sub
from crimson.perks import PerkId
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.factories import make_creature_update_options
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_radioactive_tick_deals_damage_and_spawns_fx() -> None:
    dt = 0.2
    state = GameplayState()

    player = PlayerState(index=0, pos=Vec2())
    player.perk_counts[int(PerkId.RADIOACTIVE)] = 1

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(46.0, 0.0)
    creature.hp = 50.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.collision_timer = 0.1

    fx_queue = FxQueue(capacity=8, max_count=8)

    pool.update(
        dt,
        options=make_creature_update_options(
            state=state,
            players=[player],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
            fx_queue=fx_queue,
        ),
    )

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
    assert fx_queue.count == 1


def test_radioactive_kill_awards_base_xp_and_bypasses_death_multipliers() -> None:
    dt = 0.2
    state = GameplayState()
    state.bonuses.double_experience = 5.0

    player = PlayerState(index=0, pos=Vec2(), experience=100)
    player.perk_counts[int(PerkId.RADIOACTIVE)] = 1
    player.perk_counts[int(PerkId.BLOODY_MESS_QUICK_LEARNER)] = 1

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(46.0, 0.0)
    creature.hp = 5.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.reward_value = 12.7
    creature.collision_timer = 0.1

    fx_queue = FxQueue(capacity=8, max_count=8)
    result = pool.update(
        dt,
        options=make_creature_update_options(
            state=state,
            players=[player],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
            fx_queue=fx_queue,
        ),
    )

    assert player.experience == 112
    assert not result.deaths
    assert creature.hp < 0.0
    assert_float_close(
        creature.lifecycle_stage,
        x87_pc24_sub(CREATURE_LIFECYCLE_ALIVE, float(dt)),
    )
    assert fx_queue.count == 1


def test_radioactive_sets_hp_to_one_for_type_id_one_creatures() -> None:
    dt = 0.2
    state = GameplayState()

    player = PlayerState(index=0, pos=Vec2(), experience=100)
    player.perk_counts[int(PerkId.RADIOACTIVE)] = 1

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.type_id = CreatureTypeId.LIZARD
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(46.0, 0.0)
    creature.hp = 5.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.reward_value = 12.7
    creature.collision_timer = 0.1

    fx_queue = FxQueue(capacity=8, max_count=8)
    result = pool.update(
        dt,
        options=make_creature_update_options(
            state=state,
            players=[player],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
            fx_queue=fx_queue,
        ),
    )

    assert player.experience == 100
    assert not result.deaths
    assert_float_close(creature.hp, 1.0)
    assert_float_close(creature.lifecycle_stage, CREATURE_LIFECYCLE_ALIVE)
    assert_float_close(creature.collision_timer, 0.5)
    assert fx_queue.count == 1


def test_radioactive_pulse_measures_distance_to_target_player() -> None:
    dt = 0.2
    state = GameplayState()

    # Player slot zero owns the perk, while the creature targets player slot one
    # and is only in range of that selected target.
    player1 = PlayerState(index=0, pos=Vec2(900.0, 900.0), health=100.0)
    player1.perk_counts[int(PerkId.RADIOACTIVE)] = 1
    player2 = PlayerState(index=1, pos=Vec2(), health=100.0)

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(46.0, 0.0)
    creature.hp = 50.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.collision_timer = 0.1
    creature.target_player = 1

    pool.update(
        dt,
        options=make_creature_update_options(
            state=state,
            players=[player1, player2],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        ),
    )

    assert creature.hp < 50.0
    # Kill XP is credited to player 1 (native writes the global _player_experience).
    assert player2.experience == 0


@pytest.mark.parametrize(
    ("preserve_bugs", "expected_pulse"),
    [
        (True, False),
        (False, True),
    ],
)
def test_radioactive_selects_native_player_zero_or_corrected_any_player(
    preserve_bugs: bool,
    expected_pulse: bool,
) -> None:
    dt = 0.2
    state = GameplayState(preserve_bugs=preserve_bugs)
    player0 = PlayerState(index=0, pos=Vec2(900.0, 900.0), health=100.0)
    player1 = PlayerState(index=1, pos=Vec2(), health=100.0)
    player1.perk_counts[int(PerkId.RADIOACTIVE)] = 1

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(46.0, 0.0)
    creature.hp = 50.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.collision_timer = 0.1
    creature.target_player = 1

    pool.update(
        dt,
        options=make_creature_update_options(
            state=state,
            players=[player0, player1],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        ),
    )

    assert (creature.hp < 50.0) is expected_pulse
    assert_float_close(creature.collision_timer, 0.5 if expected_pulse else 0.1)


def test_radioactive_pulse_requires_living_creature() -> None:
    dt = 0.2
    state = GameplayState()

    player = PlayerState(index=0, pos=Vec2())
    player.perk_counts[int(PerkId.RADIOACTIVE)] = 1

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.flags = CreatureFlags.ANIM_PING_PONG
    creature.pos = Vec2(46.0, 0.0)
    creature.hp = -1.0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.collision_timer = 0.1
    experience_before = player.experience

    pool.update(
        dt,
        options=make_creature_update_options(
            state=state,
            players=[player],
            rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        ),
    )

    # Native requires hp > 0 at timer fire: an already-dead creature is not
    # pulsed again (no XP re-award, no collision timer reset).
    assert player.experience == experience_before
    assert creature.collision_timer != 0.5
