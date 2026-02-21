from __future__ import annotations

import pytest

from crimson.gameplay import GameplayState
from crimson.perks import PerkId
from crimson.perks.runtime.effects import perks_update_effects
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.helpers import MockCrand, assert_float_close


@pytest.mark.parametrize(
    ("rng_value", "preserve_bugs", "has_greater_regeneration", "expected_health"),
    [
        (1, False, False, 90.2),
        (0, False, False, 90.0),
        (1, False, True, 90.4),
        (1, True, True, 90.2),
    ],
    ids=[
        "regeneration-heals-when-rng-allows",
        "regeneration-skips-when-rng-blocks",
        "greater-regeneration-doubles-heal-by-default",
        "greater-regeneration-keeps-noop-with-preserve-bugs",
    ],
)
def test_perks_update_effects_regeneration_single_player_variants(
    rng_value: int,
    preserve_bugs: bool,
    has_greater_regeneration: bool,
    expected_health: float,
) -> None:
    state = GameplayState()
    state.rng = MockCrand(rng_value)
    state.preserve_bugs = preserve_bugs

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=90.0)
    player.perk_counts[int(PerkId.REGENERATION)] = 1
    if has_greater_regeneration:
        player.perk_counts[int(PerkId.GREATER_REGENERATION)] = 1

    perks_update_effects(state, [player], 0.2)

    assert_float_close(player.health, expected_health)


@pytest.mark.parametrize(
    ("preserve_bugs", "expected_player0_health", "expected_player1_health"),
    [
        (False, 90.2, 80.2),
        (True, 90.4, 80.0),
    ],
    ids=[
        "heals-all-alive-players-by-default",
        "preserve-bugs-keeps-player1-only-scaled-tick",
    ],
)
def test_perks_update_effects_regeneration_multiplayer_targeting(
    preserve_bugs: bool,
    expected_player0_health: float,
    expected_player1_health: float,
) -> None:
    state = GameplayState()
    state.rng = MockCrand(1)
    state.preserve_bugs = preserve_bugs

    player0 = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=90.0)
    player1 = PlayerState(index=1, pos=Vec2(30.0, 40.0), health=80.0)
    player0.perk_counts[int(PerkId.REGENERATION)] = 1

    perks_update_effects(state, [player0, player1], 0.2)

    assert_float_close(player0.health, expected_player0_health)
    assert_float_close(player1.health, expected_player1_health)
