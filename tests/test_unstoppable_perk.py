from __future__ import annotations

from grim.geom import Vec2

import math

from crimson.gameplay import (
    GameplayState,
    player_update,
)
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.perks import PerkId
from crimson.player_damage import player_take_damage


def test_player_take_damage_applies_heading_jitter_and_spread_heat_without_unstoppable() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=100.0, heading=1.0, spread_heat=0.1)

    applied = player_take_damage(state, player, 10.0, rand=lambda: 0)

    assert applied == 10.0
    assert player.health == 90.0
    assert math.isclose(player.heading, -1.0, abs_tol=1e-9)  # (0 % 100 - 50) * 0.04 == -2.0
    assert math.isclose(player.spread_heat, 0.2, abs_tol=1e-9)


def test_player_take_damage_suppresses_heading_jitter_and_spread_heat_with_unstoppable() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), health=100.0, heading=1.0, spread_heat=0.1)
    player.perk_counts[int(PerkId.UNSTOPPABLE)] = 1

    applied = player_take_damage(state, player, 10.0, rand=lambda: 0)

    assert applied == 10.0
    assert player.health == 90.0
    assert math.isclose(player.heading, 1.0, abs_tol=1e-9)
    assert math.isclose(player.spread_heat, 0.1, abs_tol=1e-9)


def test_player_take_damage_heading_jitter_is_not_snapped_by_player_update() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), health=100.0, heading=1.0, move_speed=2.0)

    player_take_damage(state, player, 10.0, rand=lambda: 0)
    target_heading = Vec2(1.0, 0.0).to_heading()
    player_update(
        player,
        PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(200.0, 100.0)),
        dt=0.1,
        state=state,
    )

    assert not math.isclose(player.heading % math.tau, target_heading, abs_tol=1e-9)
