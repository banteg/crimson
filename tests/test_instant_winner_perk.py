from __future__ import annotations

from grim.geom import Vec2

from crimson.gameplay import GameplayState
from crimson.sim.state_types import PlayerState
from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply


def test_instant_winner_grants_xp_to_owner() -> None:
    state = GameplayState()
    owner = PlayerState(index=0, pos=Vec2(), experience=123)
    other = PlayerState(index=1, pos=Vec2(), experience=456)

    perk_apply(state, [owner, other], PerkId.INSTANT_WINNER)

    assert owner.experience == 2623
    assert other.experience == 456
