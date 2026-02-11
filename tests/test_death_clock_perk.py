from __future__ import annotations

from grim.geom import Vec2

import pytest

from crimson.gameplay import GameplayState, PlayerState
from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply
from crimson.perks.runtime.effects import perks_update_effects
from crimson.player_damage import player_take_damage, player_take_projectile_damage


def test_death_clock_clears_regeneration_and_restores_health() -> None:
    state = GameplayState()
    owner = PlayerState(index=0, pos=Vec2(), health=50.0)
    other = PlayerState(index=1, pos=Vec2(), health=75.0)

    owner.perk_counts[int(PerkId.REGENERATION)] = 2
    owner.perk_counts[int(PerkId.GREATER_REGENERATION)] = 1

    perk_apply(state, [owner, other], PerkId.DEATH_CLOCK)

    assert owner.perk_counts[int(PerkId.DEATH_CLOCK)] == 1
    assert owner.perk_counts[int(PerkId.REGENERATION)] == 0
    assert owner.perk_counts[int(PerkId.GREATER_REGENERATION)] == 0
    assert owner.health == 100.0

    assert other.perk_counts[int(PerkId.DEATH_CLOCK)] == 1
    assert other.perk_counts[int(PerkId.REGENERATION)] == 0
    assert other.perk_counts[int(PerkId.GREATER_REGENERATION)] == 0
    assert other.health == 100.0


def test_death_clock_blocks_damage() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=100.0)
    player.perk_counts[int(PerkId.DEATH_CLOCK)] = 1

    applied = player_take_damage(state, player, 10.0, dt=0.1, rand=lambda: 0)

    assert applied == 0.0
    assert player.health == 100.0


def test_death_clock_does_not_block_projectile_hit_path() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=100.0)
    player.perk_counts[int(PerkId.DEATH_CLOCK)] = 1

    applied = player_take_projectile_damage(state, player, 10.0)

    assert applied == 10.0
    assert player.health == 90.0


def test_death_clock_drains_health_over_time() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=100.0)
    player.perk_counts[int(PerkId.DEATH_CLOCK)] = 1

    perks_update_effects(state, [player], 1.0)

    assert player.health == pytest.approx(96.6666667)


def test_death_clock_clamps_dead_health_to_zero() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=-1.0)
    player.perk_counts[int(PerkId.DEATH_CLOCK)] = 1

    perks_update_effects(state, [player], 0.1)

    assert player.health == 0.0


def test_death_clock_tick_is_gated_by_player0_perk_state() -> None:
    state = GameplayState()
    player0 = PlayerState(index=0, pos=Vec2(), health=100.0)
    player1 = PlayerState(index=1, pos=Vec2(), health=100.0)
    player1.perk_counts[int(PerkId.DEATH_CLOCK)] = 1

    perks_update_effects(state, [player0, player1], 1.0)

    assert player0.health == 100.0
    assert player1.health == 100.0


def test_death_clock_tick_applies_to_all_players_when_player0_has_perk() -> None:
    state = GameplayState()
    player0 = PlayerState(index=0, pos=Vec2(), health=100.0)
    player1 = PlayerState(index=1, pos=Vec2(), health=100.0)
    player0.perk_counts[int(PerkId.DEATH_CLOCK)] = 1

    perks_update_effects(state, [player0, player1], 1.0)

    assert player0.health == pytest.approx(96.6666667)
    assert player1.health == pytest.approx(96.6666667)
