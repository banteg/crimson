from __future__ import annotations

from crimson.math_parity import f32, x87_pc24_mul, x87_pc24_sub
from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.helpers import assert_float_close


def test_thick_skinned_keeps_two_thirds_health() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=90.0)

    perk_apply(state, [player], PerkId.THICK_SKINNED)

    assert_float_close(
        player.health,
        x87_pc24_sub(90.0, x87_pc24_mul(90.0, f32(0.33333334))),
    )


def test_thick_skinned_rounds_multiply_before_health_subtraction() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=25.506977081298828)

    perk_apply(state, [player], PerkId.THICK_SKINNED)

    assert player.health == 17.004650115966797


def test_thick_skinned_has_no_health_floor() -> None:
    # Native's `= 1.0` clamp is dead code: it only fires when `h - h/3 <= 0`,
    # which cannot happen for positive health. At 0.1 HP (e.g. after Infernal
    # Contract) the perk reduces health rather than healing to 1.0.
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=0.1)

    perk_apply(state, [player], PerkId.THICK_SKINNED)

    assert 0.0 < player.health < 0.1


def test_thick_skinned_skips_dead_players() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=-5.0)

    perk_apply(state, [player], PerkId.THICK_SKINNED)

    assert player.health == -5.0
