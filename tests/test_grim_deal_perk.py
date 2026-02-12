from __future__ import annotations

from grim.geom import Vec2

from crimson.gameplay import GameplayState
from crimson.sim.state_types import PlayerState
from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply


def test_grim_deal_kills_owner_and_boosts_experience() -> None:
    state = GameplayState()
    owner = PlayerState(index=0, pos=Vec2(), health=100.0, experience=12345)
    other = PlayerState(index=1, pos=Vec2(), health=100.0, experience=7)

    perk_apply(state, [owner, other], PerkId.GRIM_DEAL)

    assert owner.health < 0.0
    assert owner.experience == 12345 + int(12345 * 0.18)
    assert other.health == 100.0
    assert other.experience == 7
