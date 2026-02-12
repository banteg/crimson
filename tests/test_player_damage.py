from __future__ import annotations

import pytest
from grim.geom import Vec2

from crimson.gameplay import GameplayState, PlayerState
from crimson.perks import PerkId
from crimson.player_damage import player_take_damage


def test_player_take_damage_ninja_dodges_1_in_3() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=100.0)
    player.perk_counts[int(PerkId.NINJA)] = 1

    applied = player_take_damage(state, player, 10.0, rand=lambda: 6)

    assert applied == 0.0
    assert player.health == 100.0


def test_player_take_damage_ninja_applies_damage_otherwise() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=100.0)
    player.perk_counts[int(PerkId.NINJA)] = 1

    applied = player_take_damage(state, player, 10.0, rand=lambda: 1)

    assert applied == 10.0
    assert player.health == 90.0


def test_player_take_damage_dodger_dodges_1_in_5() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=100.0)
    player.perk_counts[int(PerkId.DODGER)] = 1

    applied = player_take_damage(state, player, 10.0, rand=lambda: 10)

    assert applied == 0.0
    assert player.health == 100.0


def test_player_take_damage_ninja_has_priority_over_dodger() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=100.0)
    player.perk_counts[int(PerkId.NINJA)] = 1
    player.perk_counts[int(PerkId.DODGER)] = 1

    applied = player_take_damage(state, player, 10.0, rand=lambda: 5)

    assert applied == 10.0
    assert player.health == 90.0


def test_player_take_damage_resets_low_health_timer_on_hit() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=25.0)

    applied = player_take_damage(state, player, 10.0, rand=lambda: 3)

    assert applied == 10.0
    assert player.health == 15.0
    assert player.low_health_timer == 0.0


def test_player_take_damage_does_not_reset_low_health_timer_above_threshold() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=50.0)

    applied = player_take_damage(state, player, 10.0, rand=lambda: 3)

    assert applied == 10.0
    assert player.health == 40.0
    assert player.low_health_timer == 100.0


def test_player_take_damage_decrements_death_timer_on_death_hit() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=5.0, death_timer=16.0)

    applied = player_take_damage(state, player, 10.0, dt=0.1, rand=lambda: 0)

    assert applied == 10.0
    assert player.health == -5.0
    assert player.death_timer == 16.0 - 0.1 * 28.0


def test_player_take_damage_thick_skinned_uses_native_damage_scale_constant() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=50.90475845336914)
    player.perk_counts[int(PerkId.THICK_SKINNED)] = 1

    applied = player_take_damage(state, player, 5.238095283508301, rand=lambda: 0)

    assert applied == pytest.approx(3.4885711669921875, abs=1e-6)
    assert player.health == pytest.approx(47.41618728637695, abs=1e-6)
