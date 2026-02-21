from __future__ import annotations

import pytest

from crimson.gameplay import GameplayState
from crimson.perks import PerkId
from crimson.player_damage import player_take_damage
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.helpers import assert_float_close


@pytest.mark.parametrize(
    ("perk_counts", "rand_val", "expected_applied", "expected_health"),
    [
        ({PerkId.NINJA: 1}, 6, 0.0, 100.0),
        ({PerkId.NINJA: 1}, 1, 10.0, 90.0),
        ({PerkId.DODGER: 1}, 10, 0.0, 100.0),
        ({PerkId.NINJA: 1, PerkId.DODGER: 1}, 5, 10.0, 90.0),
    ],
    ids=[
        "ninja-dodges-1-in-3",
        "ninja-applies-damage-otherwise",
        "dodger-dodges-1-in-5",
        "ninja-has-priority-over-dodger",
    ],
)
def test_player_take_damage_dodge_perks(
    perk_counts: dict[PerkId, int],
    rand_val: int,
    expected_applied: float,
    expected_health: float,
) -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=100.0)
    for perk_id, count in perk_counts.items():
        player.perk_counts[int(perk_id)] = count

    applied = player_take_damage(state, player, 10.0, rand=lambda: rand_val)

    assert applied == expected_applied
    assert player.health == expected_health


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

    assert_float_close(applied, 3.4885711669921875)
    assert_float_close(player.health, 47.41618728637695)


def test_player_take_damage_sets_survival_damage_seen_even_when_shielded() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=100.0, shield_timer=1.0)

    applied = player_take_damage(state, player, 10.0, rand=lambda: 0)

    assert applied == 0.0
    assert state.survival_reward_damage_seen is True


def test_player_take_damage_uses_target_player_alive_guard_by_default() -> None:
    state = GameplayState(preserve_bugs=False)
    player1 = PlayerState(index=0, pos=Vec2(), health=-1.0)
    player2 = PlayerState(index=1, pos=Vec2(), health=5.0, death_timer=16.0)

    applied = player_take_damage(state, player2, 10.0, dt=0.1, rand=lambda: 0, players=[player1, player2])

    assert applied == 10.0
    assert player2.health == -5.0
    assert player2.death_timer == 16.0 - 0.1 * 28.0
    assert state.sfx_queue == ["sfx_trooper_die_01"]


def test_player_take_damage_preserve_bugs_uses_player1_alive_guard() -> None:
    state = GameplayState(preserve_bugs=True)
    player1 = PlayerState(index=0, pos=Vec2(), health=-1.0)
    player2 = PlayerState(index=1, pos=Vec2(), health=5.0, death_timer=16.0)

    applied = player_take_damage(state, player2, 10.0, dt=0.1, rand=lambda: 0, players=[player1, player2])

    assert applied == 10.0
    assert player2.health == -5.0
    assert player2.death_timer == 16.0 - 0.1 * 28.0
    assert state.sfx_queue == []
