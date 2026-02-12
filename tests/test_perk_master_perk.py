from __future__ import annotations

from grim.geom import Vec2

from crimson.sim.state_types import PlayerState
from crimson.perks import PerkId
from crimson.perks.selection import perk_choice_count


def test_perk_master_adds_two_choices() -> None:
    player = PlayerState(index=0, pos=Vec2())
    assert perk_choice_count(player) == 5

    player.perk_counts[int(PerkId.PERK_EXPERT)] = 1
    player.perk_counts[int(PerkId.PERK_MASTER)] = 1
    assert perk_choice_count(player) == 7
