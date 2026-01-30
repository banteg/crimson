from __future__ import annotations

from crimson.gameplay import GameplayState, PlayerState, perk_apply
from crimson.perks import PerkId


def test_instant_winner_grants_xp_to_owner() -> None:
    state = GameplayState()
    owner = PlayerState(index=0, pos_x=0.0, pos_y=0.0, experience=123)
    other = PlayerState(index=1, pos_x=0.0, pos_y=0.0, experience=456)

    perk_apply(state, [owner, other], PerkId.INSTANT_WINNER)

    assert owner.experience == 2623
    assert other.experience == 456
