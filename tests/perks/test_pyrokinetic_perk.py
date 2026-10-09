from __future__ import annotations

from crimson.creatures.runtime import CreatureState
from crimson.effects import FxQueue
from crimson.perks import PerkId
from crimson.perks.effects import perks_update_effects
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand
from tests.support.helpers import assert_float_close

_PYROKINETIC_BURST_CALLERS = [
    RngCallerStatic.PERKS_UPDATE_EFFECTS_PYROKINETIC_ANGLE_0P8,
    RngCallerStatic.FX_SPAWN_PARTICLE_ROTATION,
    RngCallerStatic.PERKS_UPDATE_EFFECTS_PYROKINETIC_ANGLE_0P6,
    RngCallerStatic.FX_SPAWN_PARTICLE_ROTATION,
    RngCallerStatic.PERKS_UPDATE_EFFECTS_PYROKINETIC_ANGLE_0P4,
    RngCallerStatic.FX_SPAWN_PARTICLE_ROTATION,
    RngCallerStatic.PERKS_UPDATE_EFFECTS_PYROKINETIC_ANGLE_0P3,
    RngCallerStatic.FX_SPAWN_PARTICLE_ROTATION,
    RngCallerStatic.PERKS_UPDATE_EFFECTS_PYROKINETIC_ANGLE_0P2,
    RngCallerStatic.FX_SPAWN_PARTICLE_ROTATION,
]
_FX_QUEUE_CALLERS = [
    RngCallerStatic.FX_QUEUE_ADD_RANDOM_GRAY,
    RngCallerStatic.FX_QUEUE_ADD_RANDOM_WIDTH,
    RngCallerStatic.FX_QUEUE_ADD_RANDOM_ROTATION,
    RngCallerStatic.FX_QUEUE_ADD_RANDOM_EFFECT_ID,
]


def test_perks_update_effects_pyrokinetic_defaults_to_first_alive_player_aim() -> None:
    rng = RecordingCrand(Crand(0x1234))
    state = GameplayState(rng=rng, preserve_bugs=False)

    player0 = PlayerState(index=0, pos=Vec2(), health=0.0)
    player1 = PlayerState(index=1, pos=Vec2())
    state.perks[int(PerkId.PYROKINETIC)] = 1
    player1.aim = Vec2(100.0, 200.0)

    creature = CreatureState()
    creature.active = True
    creature.pos = Vec2(100.0, 200.0)
    creature.death_timer = 16.0
    creature.dot_tick_timer = 0.1

    fx_queue = FxQueue()

    perks_update_effects(state, [player0, player1], 0.2, creatures=[creature], fx_queue=fx_queue)

    assert_float_close(creature.dot_tick_timer, 0.5)
    assert fx_queue.count == 1
    assert [record.caller for record in rng.records_since()] == [
        *_PYROKINETIC_BURST_CALLERS,
        *_FX_QUEUE_CALLERS,
    ]


def test_perks_update_effects_pyrokinetic_preserve_bugs_keeps_player0_only_targeting() -> None:
    rng = RecordingCrand(Crand(0x1234))
    state = GameplayState(rng=rng, preserve_bugs=True)

    player0 = PlayerState(index=0, pos=Vec2(), health=0.0)
    player1 = PlayerState(index=1, pos=Vec2())
    state.perks[int(PerkId.PYROKINETIC)] = 1
    player1.aim = Vec2(100.0, 200.0)

    creature = CreatureState()
    creature.active = True
    creature.pos = Vec2(100.0, 200.0)
    creature.death_timer = 16.0
    creature.dot_tick_timer = 0.1

    fx_queue = FxQueue()

    perks_update_effects(state, [player0, player1], 0.2, creatures=[creature], fx_queue=fx_queue)

    assert_float_close(creature.dot_tick_timer, 0.1)
    assert fx_queue.count == 0
    assert [record.caller for record in rng.records_since()] == []


def test_perks_update_effects_pyrokinetic_default_targets_all_alive_players() -> None:
    dt = 0.2
    rng = RecordingCrand(Crand(0x1234))
    state = GameplayState(rng=rng, preserve_bugs=False)

    player0 = PlayerState(index=0, pos=Vec2())
    player1 = PlayerState(index=1, pos=Vec2())
    state.perks[int(PerkId.PYROKINETIC)] = 1
    player0.aim = Vec2(100.0, 200.0)
    player1.aim = Vec2(140.0, 200.0)

    creature0 = CreatureState()
    creature0.active = True
    creature0.pos = Vec2(100.0, 200.0)
    creature0.death_timer = 16.0
    creature0.dot_tick_timer = 0.1

    creature1 = CreatureState()
    creature1.active = True
    creature1.pos = Vec2(140.0, 200.0)
    creature1.death_timer = 16.0
    creature1.dot_tick_timer = 0.1

    fx_queue = FxQueue()

    perks_update_effects(state, [player0, player1], dt, creatures=[creature0, creature1], fx_queue=fx_queue)

    assert_float_close(creature0.dot_tick_timer, 0.5)
    assert_float_close(creature1.dot_tick_timer, 0.5)
    assert fx_queue.count == 2
    assert [record.caller for record in rng.records_since()] == [
        *_PYROKINETIC_BURST_CALLERS,
        *_FX_QUEUE_CALLERS,
        *_PYROKINETIC_BURST_CALLERS,
        *_FX_QUEUE_CALLERS,
    ]
