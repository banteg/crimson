from __future__ import annotations

from crimson.gameplay import GameplayState
from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from grim.rand import Crand


class _FixedRng(Crand):
    def __init__(self, value: int) -> None:
        super().__init__(0)
        self._value = int(value)

    def rand(self) -> int:
        return int(self._value)


def test_fatal_lottery_grants_xp_when_rng_even() -> None:
    state = GameplayState()
    state.rng = _FixedRng(0)

    owner = PlayerState(index=0, pos=Vec2(), experience=123)
    other = PlayerState(index=1, pos=Vec2(), experience=456)

    perk_apply(state, [owner, other], PerkId.FATAL_LOTTERY)

    assert owner.experience == 10123
    assert owner.health == 100.0
    assert other.experience == 456
    assert other.health == 100.0


def test_fatal_lottery_kills_only_owner_when_rng_odd() -> None:
    state = GameplayState()
    state.rng = _FixedRng(1)

    owner = PlayerState(index=0, pos=Vec2(), health=100.0)
    other = PlayerState(index=1, pos=Vec2(), health=100.0)

    perk_apply(state, [owner, other], PerkId.FATAL_LOTTERY)

    assert owner.health < 0.0
    assert other.health == 100.0
