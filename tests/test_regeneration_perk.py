from __future__ import annotations

from crimson.gameplay import GameplayState
from crimson.perks import PerkId
from crimson.perks.runtime.effects import perks_update_effects
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.helpers import MockCrand, assert_float_close


def test_perks_update_effects_regeneration_heals_when_rng_allows() -> None:
    state = GameplayState()
    state.rng = MockCrand(1)  # rand & 1 == 1

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=90.0)
    player.perk_counts[int(PerkId.REGENERATION)] = 1

    perks_update_effects(state, [player], 0.2)

    assert_float_close(player.health, 90.2, abs_tol=1e-9)


def test_perks_update_effects_regeneration_skips_when_rng_blocks() -> None:
    state = GameplayState()
    state.rng = MockCrand(0)  # rand & 1 == 0

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=90.0)
    player.perk_counts[int(PerkId.REGENERATION)] = 1

    perks_update_effects(state, [player], 0.2)

    assert_float_close(player.health, 90.0, abs_tol=1e-9)


def test_perks_update_effects_greater_regeneration_doubles_heal_by_default() -> None:
    state = GameplayState()
    state.rng = MockCrand(1)  # rand & 1 == 1
    state.preserve_bugs = False

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=90.0)
    player.perk_counts[int(PerkId.REGENERATION)] = 1
    player.perk_counts[int(PerkId.GREATER_REGENERATION)] = 1

    perks_update_effects(state, [player], 0.2)

    assert_float_close(player.health, 90.4, abs_tol=1e-9)


def test_perks_update_effects_greater_regeneration_keeps_noop_with_preserve_bugs() -> None:
    state = GameplayState()
    state.rng = MockCrand(1)  # rand & 1 == 1
    state.preserve_bugs = True

    player = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=90.0)
    player.perk_counts[int(PerkId.REGENERATION)] = 1
    player.perk_counts[int(PerkId.GREATER_REGENERATION)] = 1

    perks_update_effects(state, [player], 0.2)

    assert_float_close(player.health, 90.2, abs_tol=1e-9)


def test_perks_update_effects_regeneration_heals_all_alive_players_by_default() -> None:
    state = GameplayState()
    state.rng = MockCrand(1)
    state.preserve_bugs = False

    player0 = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=90.0)
    player1 = PlayerState(index=1, pos=Vec2(30.0, 40.0), health=80.0)
    player0.perk_counts[int(PerkId.REGENERATION)] = 1

    perks_update_effects(state, [player0, player1], 0.2)

    assert_float_close(player0.health, 90.2, abs_tol=1e-9)
    assert_float_close(player1.health, 80.2, abs_tol=1e-9)


def test_perks_update_effects_regeneration_preserve_bugs_keeps_player1_only_scaled_tick() -> None:
    state = GameplayState()
    state.rng = MockCrand(1)
    state.preserve_bugs = True

    player0 = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=90.0)
    player1 = PlayerState(index=1, pos=Vec2(30.0, 40.0), health=80.0)
    player0.perk_counts[int(PerkId.REGENERATION)] = 1

    perks_update_effects(state, [player0, player1], 0.2)

    assert_float_close(player0.health, 90.4, abs_tol=1e-9)
    assert_float_close(player1.health, 80.0, abs_tol=1e-9)
