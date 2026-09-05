from __future__ import annotations

import pytest

from crimson.perks import PerkId
from crimson.player_damage import player_take_damage
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand


@pytest.mark.parametrize(
    ("rand_val", "expected_applied", "expected_health"),
    [
        (1, 0.0, 100.0),
        (0, 100.0, 0.0),
    ],
    ids=["prevents-damage-most-of-the-time", "kills-1-in-10"],
)
def test_player_take_damage_highlander_behavior(
    rand_val: int,
    expected_applied: float,
    expected_health: float,
) -> None:
    state = GameplayState(rng=ScriptedCrand(rand_val, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2(), health=100.0)
    player.perk_counts[int(PerkId.HIGHLANDER)] = 1
    player.perk_counts[int(PerkId.UNSTOPPABLE)] = 1

    applied = player_take_damage(state, player, 10.0)

    assert applied == expected_applied
    assert player.health == expected_health
