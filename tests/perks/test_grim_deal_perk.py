from __future__ import annotations

from crimson.gameplay import GameplayState
from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2


def test_grim_deal_kills_owner_and_boosts_experience() -> None:
    state = GameplayState()
    owner = PlayerState(index=0, pos=Vec2(), health=100.0, experience=12345)
    other = PlayerState(index=1, pos=Vec2(), health=100.0, experience=7)

    perk_apply(state, [owner, other], PerkId.GRIM_DEAL)

    assert owner.health < 0.0
    assert owner.experience == 12345 + int(12345 * 0.18)
    assert other.health == 100.0
    assert other.experience == 7


def test_grim_deal_uses_native_float_scale_before_truncation() -> None:
    state = GameplayState()
    owner = PlayerState(index=0, pos=Vec2(), experience=1_456_361)

    perk_apply(state, [owner], PerkId.GRIM_DEAL)

    # Native 0.18f multiplication rounds to 262145 at x87 PC=24. A Python
    # double 0.18 produces 262144 and loses one experience point here.
    assert owner.experience == 1_718_506
