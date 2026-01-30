from __future__ import annotations

from crimson.gameplay import perk_can_offer
from crimson.gameplay import PlayerState
from crimson.perks import PERK_BY_ID, PerkId


def test_antiperk_is_never_offered() -> None:
    meta = PERK_BY_ID[int(PerkId.ANTIPERK)]
    assert not perk_can_offer(PlayerState(index=0, pos_x=0.0, pos_y=0.0), meta, game_mode=0, player_count=1)
