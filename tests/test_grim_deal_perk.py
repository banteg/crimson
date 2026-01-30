from __future__ import annotations

from crimson.gameplay import GameplayState, PlayerState, perk_apply
from crimson.perks import PerkId


def test_grim_deal_kills_owner_and_boosts_experience() -> None:
    state = GameplayState()
    owner = PlayerState(index=0, pos_x=0.0, pos_y=0.0, health=100.0, experience=12345)
    other = PlayerState(index=1, pos_x=0.0, pos_y=0.0, health=100.0, experience=7)

    perk_apply(state, [owner, other], PerkId.GRIM_DEAL)

    assert owner.health < 0.0
    assert owner.experience == 12345 + int(12345 * 0.18)
    assert other.health == 100.0
    assert other.experience == 7
