from __future__ import annotations

from crimson.creatures.runtime import CreatureState
from crimson.effects import FxQueue
from crimson.gameplay import GameplayState
from crimson.math_parity import f32
from crimson.perks import PerkId
from crimson.perks.runtime.effects import perks_update_effects
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand, assert_float_close

_PYROKINETIC_BURST_CALLERS = [
    RngCallerStatic.PERKS_UPDATE_EFFECTS_PYROKINETIC_ANGLE_0P8,
    RngCallerStatic.FX_SPAWN_PARTICLE_SPIN,
    RngCallerStatic.PERKS_UPDATE_EFFECTS_PYROKINETIC_ANGLE_0P6,
    RngCallerStatic.FX_SPAWN_PARTICLE_SPIN,
    RngCallerStatic.PERKS_UPDATE_EFFECTS_PYROKINETIC_ANGLE_0P4,
    RngCallerStatic.FX_SPAWN_PARTICLE_SPIN,
    RngCallerStatic.PERKS_UPDATE_EFFECTS_PYROKINETIC_ANGLE_0P3,
    RngCallerStatic.FX_SPAWN_PARTICLE_SPIN,
    RngCallerStatic.PERKS_UPDATE_EFFECTS_PYROKINETIC_ANGLE_0P2,
    RngCallerStatic.FX_SPAWN_PARTICLE_SPIN,
]
_FX_QUEUE_CALLERS = [
    RngCallerStatic.FX_QUEUE_ADD_RANDOM_GRAY,
    RngCallerStatic.FX_QUEUE_ADD_RANDOM_WIDTH,
    RngCallerStatic.FX_QUEUE_ADD_RANDOM_ROTATION,
    RngCallerStatic.FX_QUEUE_ADD_RANDOM_EFFECT_ID,
]


def test_perks_update_effects_pyrokinetic_spawns_particle_burst_when_timer_wraps() -> None:
    dt = 0.2
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    state = GameplayState(rng=rng)

    player = PlayerState(index=0, pos=Vec2())
    player.perk_counts[int(PerkId.PYROKINETIC)] = 1
    player.aim = Vec2(100.0, 200.0)

    creature = CreatureState()
    creature.active = True
    creature.pos = Vec2(100.0, 200.0)
    creature.lifecycle_stage = 16.0
    creature.collision_timer = 0.1

    fx_queue = FxQueue(capacity=8, max_count=8)

    perks_update_effects(state, [player], dt, creatures=[creature], fx_queue=fx_queue)

    assert_float_close(creature.collision_timer, 0.5)
    assert fx_queue.count == 1

    particles = [entry for entry in state.particles.entries if entry.active]
    assert len(particles) == 5
    intensities = [entry.intensity for entry in particles]
    assert intensities == [f32(value) for value in (0.8, 0.6, 0.4, 0.3, 0.2)]
    assert [record.caller for record in rng.records_since()] == [
        *_PYROKINETIC_BURST_CALLERS,
        *_FX_QUEUE_CALLERS,
    ]


def test_perks_update_effects_pyrokinetic_uses_f32_timer_threshold_before_wrapping() -> None:
    # Captured survival run (ticks 4055/4056) sits exactly on the timer boundary;
    # float32 math must avoid wrapping one tick early.
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    state = GameplayState(rng=rng)

    player = PlayerState(index=0, pos=Vec2())
    player.perk_counts[int(PerkId.PYROKINETIC)] = 1
    player.aim = Vec2(100.0, 200.0)

    creature = CreatureState()
    creature.active = True
    creature.pos = Vec2(100.0, 200.0)
    creature.lifecycle_stage = 16.0
    creature.collision_timer = 0.034000009298324585

    fx_queue = FxQueue(capacity=8, max_count=8)

    perks_update_effects(
        state,
        [player],
        0.03400000184774399,
        creatures=[creature],
        fx_queue=fx_queue,
    )
    assert 0.0 < creature.collision_timer < 1e-6
    assert fx_queue.count == 0
    assert all(not entry.active for entry in state.particles.entries)
    assert [record.caller for record in rng.records_since()] == []

    perks_update_effects(
        state,
        [player],
        0.03200000151991844,
        creatures=[creature],
        fx_queue=fx_queue,
    )
    assert_float_close(creature.collision_timer, 0.5)
    assert fx_queue.count == 1
    particles = [entry for entry in state.particles.entries if entry.active]
    assert len(particles) == 5
    assert [record.caller for record in rng.records_since()] == [
        *_PYROKINETIC_BURST_CALLERS,
        *_FX_QUEUE_CALLERS,
    ]


def test_perks_update_effects_pyrokinetic_defaults_to_first_alive_player_aim() -> None:
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    state = GameplayState(rng=rng, preserve_bugs=False)

    player0 = PlayerState(index=0, pos=Vec2(), health=0.0)
    player1 = PlayerState(index=1, pos=Vec2())
    player1.perk_counts[int(PerkId.PYROKINETIC)] = 1
    player1.aim = Vec2(100.0, 200.0)

    creature = CreatureState()
    creature.active = True
    creature.pos = Vec2(100.0, 200.0)
    creature.lifecycle_stage = 16.0
    creature.collision_timer = 0.1

    fx_queue = FxQueue(capacity=8, max_count=8)

    perks_update_effects(state, [player0, player1], 0.2, creatures=[creature], fx_queue=fx_queue)

    assert_float_close(creature.collision_timer, 0.5)
    assert fx_queue.count == 1
    assert [record.caller for record in rng.records_since()] == [
        *_PYROKINETIC_BURST_CALLERS,
        *_FX_QUEUE_CALLERS,
    ]


def test_perks_update_effects_pyrokinetic_preserve_bugs_keeps_player0_only_targeting() -> None:
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    state = GameplayState(rng=rng, preserve_bugs=True)

    player0 = PlayerState(index=0, pos=Vec2(), health=0.0)
    player1 = PlayerState(index=1, pos=Vec2())
    player1.perk_counts[int(PerkId.PYROKINETIC)] = 1
    player1.aim = Vec2(100.0, 200.0)

    creature = CreatureState()
    creature.active = True
    creature.pos = Vec2(100.0, 200.0)
    creature.lifecycle_stage = 16.0
    creature.collision_timer = 0.1

    fx_queue = FxQueue(capacity=8, max_count=8)

    perks_update_effects(state, [player0, player1], 0.2, creatures=[creature], fx_queue=fx_queue)

    assert_float_close(creature.collision_timer, 0.1)
    assert fx_queue.count == 0
    assert [record.caller for record in rng.records_since()] == []


def test_perks_update_effects_pyrokinetic_default_targets_all_alive_players() -> None:
    dt = 0.2
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    state = GameplayState(rng=rng, preserve_bugs=False)

    player0 = PlayerState(index=0, pos=Vec2())
    player1 = PlayerState(index=1, pos=Vec2())
    player0.perk_counts[int(PerkId.PYROKINETIC)] = 1
    player1.perk_counts[int(PerkId.PYROKINETIC)] = 1
    player0.aim = Vec2(100.0, 200.0)
    player1.aim = Vec2(140.0, 200.0)

    creature0 = CreatureState()
    creature0.active = True
    creature0.pos = Vec2(100.0, 200.0)
    creature0.lifecycle_stage = 16.0
    creature0.collision_timer = 0.1

    creature1 = CreatureState()
    creature1.active = True
    creature1.pos = Vec2(140.0, 200.0)
    creature1.lifecycle_stage = 16.0
    creature1.collision_timer = 0.1

    fx_queue = FxQueue(capacity=16, max_count=16)

    perks_update_effects(state, [player0, player1], dt, creatures=[creature0, creature1], fx_queue=fx_queue)

    assert_float_close(creature0.collision_timer, 0.5)
    assert_float_close(creature1.collision_timer, 0.5)
    assert fx_queue.count == 2
    assert [record.caller for record in rng.records_since()] == [
        *_PYROKINETIC_BURST_CALLERS,
        *_FX_QUEUE_CALLERS,
        *_PYROKINETIC_BURST_CALLERS,
        *_FX_QUEUE_CALLERS,
    ]
