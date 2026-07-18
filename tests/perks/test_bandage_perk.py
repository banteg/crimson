from __future__ import annotations

from crimson.gameplay import GameplayState
from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand

_BURST_CALLERS = [
    RngCallerStatic.EFFECT_SPAWN_BURST_ROTATION,
    RngCallerStatic.EFFECT_SPAWN_BURST_VEL_X,
    RngCallerStatic.EFFECT_SPAWN_BURST_VEL_Y,
    RngCallerStatic.EFFECT_SPAWN_BURST_SCALE_STEP,
]


def test_bandage_clamps_health_and_spawns_burst() -> None:
    state = GameplayState()
    state.rng = ScriptedCrand(49, fallback=ScriptedCrand.Fallback.REPEAT_LAST)  # (rand % 50) + 1 == 50

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=3.0)
    perk_apply(state, [player], PerkId.BANDAGE)

    assert player.health == 53.0
    assert len(state.effects.iter_active()) == 8
    assert [record.caller for record in state.rng.records_since()] == [
        RngCallerStatic.PERK_APPLY_BANDAGE_HEAL,
        *(_BURST_CALLERS * 8),
    ]


def test_bandage_preserve_bugs_keeps_native_multiplier_behavior() -> None:
    state = GameplayState()
    state.preserve_bugs = True
    state.rng = ScriptedCrand(49, fallback=ScriptedCrand.Fallback.REPEAT_LAST)  # (rand % 50) + 1 == 50

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=3.0)
    perk_apply(state, [player], PerkId.BANDAGE)

    assert player.health == 100.0
    assert len(state.effects.iter_active()) == 8
    assert [record.caller for record in state.rng.records_since()] == [
        RngCallerStatic.PERK_APPLY_BANDAGE_HEAL,
        *(_BURST_CALLERS * 8),
    ]


def test_bandage_rounds_native_health_store() -> None:
    state = GameplayState()
    state.preserve_bugs = True
    state.rng = ScriptedCrand(2, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    player = PlayerState(index=0, pos=Vec2(), health=0.1)

    perk_apply(state, [player], PerkId.BANDAGE)

    assert player.health == 0.30000001192092896


def test_bandage_preserve_bugs_draws_for_dead_players() -> None:
    state = GameplayState()
    state.preserve_bugs = True
    state.rng = ScriptedCrand(49, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    alive = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=3.0)
    dead = PlayerState(index=1, pos=Vec2(30.0, 40.0), health=-5.0)
    perk_apply(state, [alive, dead], PerkId.BANDAGE)

    # Native has no alive gate: the dead player consumes a rand, has its
    # negative health multiplied, and spawns a burst at the corpse.
    assert alive.health == 100.0
    assert dead.health == -250.0
    assert len(state.effects.iter_active()) == 16
    assert [record.caller for record in state.rng.records_since()] == [
        RngCallerStatic.PERK_APPLY_BANDAGE_HEAL,
        *(_BURST_CALLERS * 8),
        RngCallerStatic.PERK_APPLY_BANDAGE_HEAL,
        *(_BURST_CALLERS * 8),
    ]


def test_bandage_default_skips_dead_players() -> None:
    state = GameplayState()
    state.rng = ScriptedCrand(49, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    alive = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=3.0)
    dead = PlayerState(index=1, pos=Vec2(30.0, 40.0), health=-5.0)
    perk_apply(state, [alive, dead], PerkId.BANDAGE)

    assert alive.health == 53.0
    assert dead.health == -5.0
    assert len(state.effects.iter_active()) == 8
