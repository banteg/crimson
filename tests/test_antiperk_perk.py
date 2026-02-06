from __future__ import annotations

from grim.geom import Vec2

from crimson.gameplay import GameplayState, PlayerState, perk_can_offer
from crimson.game_modes import GameMode
from crimson.perks import PerkId


def test_antiperk_is_never_offered() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    assert not perk_can_offer(state, player, PerkId.ANTIPERK, game_mode=int(GameMode.SURVIVAL), player_count=1)
