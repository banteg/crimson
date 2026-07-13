from __future__ import annotations

import math

from crimson.gameplay import (
    GameplayState,
    player_update,
)
from crimson.math_parity import f32, x87_pc24_add, x87_pc24_mul
from crimson.perks import PerkId
from crimson.player_damage import player_take_damage
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_player_take_damage_applies_heading_jitter_and_spread_heat_without_unstoppable() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2(), health=100.0, heading=1.0, spread_heat=0.1)

    applied = player_take_damage(state, player, 10.0)

    assert applied == 10.0
    assert player.health == 90.0
    assert_float_close(player.heading, -1.0)  # (0 % 100 - 50) * 0.04 == -2.0
    assert player.spread_heat == x87_pc24_add(0.1, x87_pc24_mul(10.0, f32(0.01)))


def test_player_take_damage_suppresses_heading_jitter_and_spread_heat_with_unstoppable() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2(), health=100.0, heading=1.0, spread_heat=0.1)
    player.perk_counts[int(PerkId.UNSTOPPABLE)] = 1

    applied = player_take_damage(state, player, 10.0)

    assert applied == 10.0
    assert player.health == 90.0
    assert_float_close(player.heading, 1.0)
    assert_float_close(player.spread_heat, 0.1)


def test_player_take_damage_heading_jitter_is_not_snapped_by_player_update() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), health=100.0, heading=1.0, move_speed=2.0)

    player_take_damage(state, player, 10.0)
    target_heading = Vec2(1.0, 0.0).to_heading()
    player_update(
        player,
        PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(200.0, 100.0)),
        dt=0.1,
        state=state,
    )

    assert abs((player.heading % math.tau) - target_heading) > 1e-6
