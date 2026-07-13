from __future__ import annotations

import pytest

from crimson.gameplay import GameplayState
from crimson.math_parity import f32, x87_pc24_add, x87_pc24_mul, x87_pc24_sub
from crimson.perks import PerkId
from crimson.player_damage import player_take_damage
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from grim.sfx_map import SfxId
from tests.support.helpers import ScriptedCrand, assert_float_close


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
    state = GameplayState(rng=ScriptedCrand(rand_val, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2(), health=100.0)
    for perk_id, count in perk_counts.items():
        player.perk_counts[int(perk_id)] = count

    applied = player_take_damage(state, player, 10.0)

    assert applied == expected_applied
    assert player.health == expected_health


def test_player_take_damage_tags_ninja_dodge_caller() -> None:
    rng = ScriptedCrand([0, 0])
    state = GameplayState(rng=rng)
    player = PlayerState(index=0, pos=Vec2(), health=100.0)
    player.perk_counts[int(PerkId.NINJA)] = 1

    applied = player_take_damage(state, player, 10.0)

    assert applied == 0.0
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PLAYER_TAKE_DAMAGE_NINJA,
        RngCallerStatic.PLAYER_TAKE_DAMAGE_PAIN_SFX,
    ]


def test_player_take_damage_tags_dodger_dodge_caller() -> None:
    rng = ScriptedCrand([0, 0])
    state = GameplayState(rng=rng)
    player = PlayerState(index=0, pos=Vec2(), health=100.0)
    player.perk_counts[int(PerkId.DODGER)] = 1

    applied = player_take_damage(state, player, 10.0)

    assert applied == 0.0
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PLAYER_TAKE_DAMAGE_DODGER,
        RngCallerStatic.PLAYER_TAKE_DAMAGE_PAIN_SFX,
    ]


def test_repeated_heading_jitter_stores_each_native_precision_result() -> None:
    state = GameplayState(rng=ScriptedCrand([0, 43, 0, 15]))
    player = PlayerState(index=0, pos=Vec2(), health=100.0, heading=f32(1.1))

    player_take_damage(state, player, 1.0)
    player_take_damage(state, player, 1.0)

    expected = x87_pc24_add(
        x87_pc24_add(f32(1.1), x87_pc24_mul(-7.0, f32(0.04))),
        x87_pc24_mul(-35.0, f32(0.04)),
    )
    assert player.heading == expected


@pytest.mark.parametrize(
    ("start_health", "expected_health", "expected_low_health_timer"),
    [
        (25.0, 15.0, 0.0),
        (50.0, 40.0, 100.0),
    ],
    ids=["resets-low-health-timer-on-hit", "does-not-reset-low-health-timer-above-threshold"],
)
def test_player_take_damage_low_health_timer_behavior(
    start_health: float,
    expected_health: float,
    expected_low_health_timer: float,
) -> None:
    state = GameplayState(rng=ScriptedCrand(3, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2(), health=start_health)

    applied = player_take_damage(state, player, 10.0)

    assert applied == 10.0
    assert player.health == expected_health
    assert player.low_health_timer == expected_low_health_timer


def test_player_take_damage_decrements_death_timer_on_death_hit() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2(), health=5.0, death_timer=16.0)

    applied = player_take_damage(state, player, 10.0, dt=0.1)

    assert applied == 10.0
    assert player.health == -5.0
    assert player.death_timer == x87_pc24_sub(16.0, x87_pc24_mul(f32(0.1), 28.0))


def test_player_take_damage_exact_zero_kill_uses_death_path_by_default() -> None:
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    state = GameplayState(preserve_bugs=False, rng=rng)
    player = PlayerState(index=0, pos=Vec2(), health=100.0, death_timer=16.0)
    player.perk_counts[int(PerkId.HIGHLANDER)] = 1

    applied = player_take_damage(state, player, 10.0, dt=0.1)

    assert applied == 100.0
    assert player.health == 0.0
    assert player.death_timer == x87_pc24_sub(16.0, x87_pc24_mul(f32(0.1), 28.0))
    assert state.sfx_queue == [SfxId.TROOPER_DIE_01]
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PLAYER_TAKE_DAMAGE_HIGHLANDER,
        RngCallerStatic.PLAYER_TAKE_DAMAGE_DEATH_SFX,
        RngCallerStatic.PLAYER_TAKE_DAMAGE_HEADING,
        RngCallerStatic.PLAYER_TAKE_DAMAGE_LOW_HEALTH,
    ]


def test_player_take_damage_exact_zero_kill_preserve_bugs_keeps_pain_path() -> None:
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    state = GameplayState(preserve_bugs=True, rng=rng)
    player = PlayerState(index=0, pos=Vec2(), health=100.0, death_timer=16.0)
    player.perk_counts[int(PerkId.HIGHLANDER)] = 1

    applied = player_take_damage(state, player, 10.0, dt=0.1)

    assert applied == 100.0
    assert player.health == 0.0
    assert player.death_timer == 16.0
    assert state.sfx_queue == [SfxId.TROOPER_INPAIN_01]
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PLAYER_TAKE_DAMAGE_HIGHLANDER,
        RngCallerStatic.PLAYER_TAKE_DAMAGE_PAIN_SFX,
        RngCallerStatic.PLAYER_TAKE_DAMAGE_HEADING,
        RngCallerStatic.PLAYER_TAKE_DAMAGE_LOW_HEALTH,
    ]


def test_player_take_damage_thick_skinned_uses_native_damage_scale_constant() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2(), health=50.90475845336914)
    player.perk_counts[int(PerkId.THICK_SKINNED)] = 1

    applied = player_take_damage(state, player, 5.238095283508301)

    assert_float_close(applied, 3.4885711669921875)
    assert_float_close(player.health, 47.41618728637695)


def test_player_take_damage_sets_survival_damage_seen_even_when_shielded() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2(), health=100.0, shield_timer=1.0)

    applied = player_take_damage(state, player, 10.0)

    assert applied == 0.0
    assert state.survival_reward_damage_seen is True


def test_player_take_damage_zero_contact_damage_preserves_native_side_effects() -> None:
    rng = ScriptedCrand([1, 50])
    state = GameplayState(rng=rng)
    player = PlayerState(index=0, pos=Vec2(), health=100.0, heading=1.0)

    applied = player_take_damage(state, player, 0.0, dt=0.1)

    assert applied == 0.0
    assert player.health == 100.0
    assert player.heading == 1.0
    assert state.survival_reward_damage_seen is True
    assert state.sfx_queue == [SfxId.TROOPER_INPAIN_02]
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PLAYER_TAKE_DAMAGE_PAIN_SFX,
        RngCallerStatic.PLAYER_TAKE_DAMAGE_HEADING,
    ]


def test_player_take_damage_uses_target_player_alive_guard_by_default() -> None:
    state = GameplayState(preserve_bugs=False, rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player1 = PlayerState(index=0, pos=Vec2(), health=-1.0)
    player2 = PlayerState(index=1, pos=Vec2(), health=5.0, death_timer=16.0)

    applied = player_take_damage(state, player2, 10.0, dt=0.1, players=[player1, player2])

    assert applied == 10.0
    assert player2.health == -5.0
    assert player2.death_timer == x87_pc24_sub(16.0, x87_pc24_mul(f32(0.1), 28.0))
    assert state.sfx_queue == [SfxId.TROOPER_DIE_01]


def test_player_take_damage_preserve_bugs_uses_player1_alive_guard() -> None:
    state = GameplayState(preserve_bugs=True, rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player1 = PlayerState(index=0, pos=Vec2(), health=-1.0)
    player2 = PlayerState(index=1, pos=Vec2(), health=5.0, death_timer=16.0)

    applied = player_take_damage(state, player2, 10.0, dt=0.1, players=[player1, player2])

    assert applied == 10.0
    assert player2.health == -5.0
    assert player2.death_timer == x87_pc24_sub(16.0, x87_pc24_mul(f32(0.1), 28.0))
    assert state.sfx_queue == []
