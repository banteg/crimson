from __future__ import annotations

from crimson.perks import PerkId
from crimson.perks.selection import perk_choice_count
from crimson.sim.state_types import PerkCounts


def test_perk_master_adds_two_choices() -> None:
    perks = PerkCounts()
    assert perk_choice_count(perks) == 5

    perks[int(PerkId.PERK_EXPERT)] = 1
    perks[int(PerkId.PERK_MASTER)] = 1
    assert perk_choice_count(perks) == 7
