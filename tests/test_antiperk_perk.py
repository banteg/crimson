from __future__ import annotations

from crimson.game_modes import GameMode
from crimson.gameplay import GameplayState
from crimson.perks import PerkId
from crimson.perks.availability import perk_can_offer
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2


def test_antiperk_is_never_offered() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    assert not perk_can_offer(state, player, PerkId.ANTIPERK, game_mode=int(GameMode.SURVIVAL), player_count=1)
