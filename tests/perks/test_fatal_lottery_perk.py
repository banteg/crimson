from __future__ import annotations

from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand


def test_fatal_lottery_grants_xp_when_rng_even() -> None:
    state = GameplayState()
    state.rng = ScriptedCrand(0)

    owner = PlayerState(index=0, pos=Vec2(), experience=123)
    other = PlayerState(index=1, pos=Vec2(), experience=456)

    perk_apply(state, [owner, other], PerkId.FATAL_LOTTERY)

    assert owner.experience == 10123
    assert owner.health == 100.0
    assert other.experience == 456
    assert other.health == 100.0
    assert [record.caller for record in state.rng.records_since()] == [
        RngCallerStatic.PERK_APPLY_FATAL_LOTTERY,
    ]


def test_fatal_lottery_kills_only_owner_when_rng_odd() -> None:
    state = GameplayState()
    state.rng = ScriptedCrand(1)

    owner = PlayerState(index=0, pos=Vec2(), health=100.0)
    other = PlayerState(index=1, pos=Vec2(), health=100.0)

    perk_apply(state, [owner, other], PerkId.FATAL_LOTTERY)

    assert owner.health < 0.0
    assert other.health == 100.0
    assert [record.caller for record in state.rng.records_since()] == [
        RngCallerStatic.PERK_APPLY_FATAL_LOTTERY,
    ]
