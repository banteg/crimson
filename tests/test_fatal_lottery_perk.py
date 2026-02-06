from __future__ import annotations

from grim.geom import Vec2

from crimson.gameplay import GameplayState, PlayerState, perk_apply
from crimson.perks import PerkId


class _FixedRng:
    def __init__(self, value: int) -> None:
        self._value = int(value)

    def rand(self) -> int:
        return int(self._value)


def test_fatal_lottery_grants_xp_when_rng_even() -> None:
    state = GameplayState()
    state.rng = _FixedRng(0)

    owner = PlayerState(index=0, pos=Vec2(0.0, 0.0), experience=123)
    other = PlayerState(index=1, pos=Vec2(0.0, 0.0), experience=456)

    perk_apply(state, [owner, other], PerkId.FATAL_LOTTERY)

    assert owner.experience == 10123
    assert owner.health == 100.0
    assert other.experience == 456
    assert other.health == 100.0


def test_fatal_lottery_kills_only_owner_when_rng_odd() -> None:
    state = GameplayState()
    state.rng = _FixedRng(1)

    owner = PlayerState(index=0, pos=Vec2(0.0, 0.0), health=100.0)
    other = PlayerState(index=1, pos=Vec2(0.0, 0.0), health=100.0)

    perk_apply(state, [owner, other], PerkId.FATAL_LOTTERY)

    assert owner.health < 0.0
    assert other.health == 100.0
