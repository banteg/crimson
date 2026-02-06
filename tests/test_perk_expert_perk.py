from __future__ import annotations

from grim.geom import Vec2

from crimson.gameplay import perk_choice_count
from crimson.gameplay import PlayerState
from crimson.perks import PerkId


def test_perk_expert_adds_one_choice() -> None:
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    assert perk_choice_count(player) == 5

    player.perk_counts[int(PerkId.PERK_EXPERT)] = 1
    assert perk_choice_count(player) == 6
