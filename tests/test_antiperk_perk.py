from __future__ import annotations

from crimson.gameplay import GameplayState, PlayerState, perk_can_offer
from crimson.game_modes import GameMode
from crimson.perks import PerkId


def test_antiperk_is_never_offered() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos_x=0.0, pos_y=0.0)
    assert not perk_can_offer(state, player, PerkId.ANTIPERK, game_mode=int(GameMode.SURVIVAL), player_count=1)
