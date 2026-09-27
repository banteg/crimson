from __future__ import annotations

import pytest

from crimson.creatures.runtime import CreaturePool
from crimson.effects import FxQueue
from crimson.math_parity import f32, x87_pc24_mul, x87_pc24_sub
from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply
from crimson.perks.runtime.effects import perks_update_effects
from crimson.player_damage import player_take_damage, player_take_projectile_damage
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_death_clock_clears_regeneration_and_restores_health() -> None:
    state = GameplayState()
    owner = PlayerState(index=0, pos=Vec2(), health=50.0)
    other = PlayerState(index=1, pos=Vec2(), health=75.0)

    state.perks[int(PerkId.REGENERATION)] = 2
    state.perks[int(PerkId.GREATER_REGENERATION)] = 1

    perk_apply(state, [owner, other], PerkId.DEATH_CLOCK)

    assert state.perks[int(PerkId.DEATH_CLOCK)] == 1
    assert state.perks[int(PerkId.REGENERATION)] == 0
    assert state.perks[int(PerkId.GREATER_REGENERATION)] == 0
    assert owner.health == 100.0
    assert other.health == 100.0


def test_death_clock_blocks_damage() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2(), health=100.0)
    state.perks[int(PerkId.DEATH_CLOCK)] = 1

    applied = player_take_damage(state, player, 10.0, dt=0.1)

    assert applied == 0.0
    assert player.health == 100.0


@pytest.mark.parametrize(("preserve_bugs", "health"), [(False, 100.0), (True, 90.0)])
def test_death_clock_blocks_enemy_projectiles_unless_preserving_bugs(preserve_bugs: bool, health: float) -> None:
    # Native projectile_update subtracts the hit directly, past the immunity (bug #27).
    state = GameplayState(preserve_bugs=preserve_bugs)
    player = PlayerState(index=0, pos=Vec2(), health=100.0)
    state.perks[int(PerkId.DEATH_CLOCK)] = 1

    player_take_projectile_damage(state, player, 10.0)

    assert player.health == health


def test_death_clock_drains_health_over_time() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=100.0)
    state.perks[int(PerkId.DEATH_CLOCK)] = 1

    perks_update_effects(state, [player], 1.0, creatures=CreaturePool().entries, fx_queue=FxQueue())

    assert_float_close(
        player.health,
        x87_pc24_sub(
            f32(100.0),
            x87_pc24_mul(f32(1.0), f32(3.33333325)),
        ),
    )


def test_death_clock_reaches_native_zero_crossing_at_30hz() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=100.0)
    state.perks[int(PerkId.DEATH_CLOCK)] = 1

    for _ in range(900):
        perks_update_effects(state, [player], 1.0 / 30.0, creatures=CreaturePool().entries, fx_queue=FxQueue())

    assert player.health == -0.0008849054574966431

    perks_update_effects(state, [player], 1.0 / 30.0, creatures=CreaturePool().entries, fx_queue=FxQueue())

    assert player.health == 0.0


def test_death_clock_clamps_dead_health_to_zero() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=-1.0)
    state.perks[int(PerkId.DEATH_CLOCK)] = 1

    perks_update_effects(state, [player], 0.1, creatures=CreaturePool().entries, fx_queue=FxQueue())

    assert player.health == 0.0


def test_death_clock_tick_applies_to_all_players() -> None:
    state = GameplayState()
    player0 = PlayerState(index=0, pos=Vec2(), health=100.0)
    player1 = PlayerState(index=1, pos=Vec2(), health=100.0)
    state.perks[int(PerkId.DEATH_CLOCK)] = 1

    perks_update_effects(state, [player0, player1], 1.0, creatures=CreaturePool().entries, fx_queue=FxQueue())

    expected = x87_pc24_sub(
        f32(100.0),
        x87_pc24_mul(f32(1.0), f32(3.33333325)),
    )
    assert_float_close(player0.health, expected)
    assert_float_close(player1.health, expected)
