from __future__ import annotations

import pytest

from crimson.perks import PerkId
from crimson.player_damage import player_take_damage
from tests.support.builders.session import make_world
from tests.support.factories import make_step_runtime
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
    world = make_world()
    state = world.state
    state.rng = ScriptedCrand(rand_val, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    player = world.players[0]
    state.perks[int(PerkId.HIGHLANDER)] = 1
    state.perks[int(PerkId.UNSTOPPABLE)] = 1

    applied = player_take_damage(make_step_runtime(world), player, 10.0, dt=0.1)

    assert applied == expected_applied
    assert player.health == expected_health
