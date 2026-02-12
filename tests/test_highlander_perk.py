from __future__ import annotations

from grim.geom import Vec2

from crimson.gameplay import GameplayState
from crimson.sim.state_types import PlayerState
from crimson.perks import PerkId
from crimson.player_damage import player_take_damage


def test_player_take_damage_highlander_prevents_damage_most_of_the_time() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=100.0)
    player.perk_counts[int(PerkId.HIGHLANDER)] = 1
    player.perk_counts[int(PerkId.UNSTOPPABLE)] = 1

    applied = player_take_damage(state, player, 10.0, rand=lambda: 1)

    assert applied == 0.0
    assert player.health == 100.0


def test_player_take_damage_highlander_kills_1_in_10() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=100.0)
    player.perk_counts[int(PerkId.HIGHLANDER)] = 1
    player.perk_counts[int(PerkId.UNSTOPPABLE)] = 1

    applied = player_take_damage(state, player, 10.0, rand=lambda: 0)

    assert applied == 100.0
    assert player.health == 0.0

