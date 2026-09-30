from __future__ import annotations

import math

from crimson.math_parity import f32, x87_pc24_add, x87_pc24_mul
from crimson.perks import PerkId
from crimson.player_damage import player_take_damage
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import make_step_runtime, player_input, step_player
from tests.support.helpers import ScriptedCrand, assert_float_close


def _scripted_world() -> WorldState:
    world = make_world()
    world.state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    return world


def test_player_take_damage_applies_heading_jitter_and_spread_heat_without_unstoppable() -> None:
    world = _scripted_world()
    player = world.players[0]
    player.heading = 1.0
    player.spread_heat = 0.1

    applied = player_take_damage(make_step_runtime(world), player, 10.0, dt=0.1)

    assert applied == 10.0
    assert player.health == 90.0
    assert_float_close(player.heading, -1.0)  # (0 % 100 - 50) * 0.04 == -2.0
    assert player.spread_heat == x87_pc24_add(0.1, x87_pc24_mul(10.0, f32(0.01)))


def test_player_take_damage_suppresses_heading_jitter_and_spread_heat_with_unstoppable() -> None:
    world = _scripted_world()
    player = world.players[0]
    player.heading = 1.0
    player.spread_heat = 0.1
    world.state.perks[int(PerkId.UNSTOPPABLE)] = 1

    applied = player_take_damage(make_step_runtime(world), player, 10.0, dt=0.1)

    assert applied == 10.0
    assert player.health == 90.0
    assert_float_close(player.heading, 1.0)
    assert_float_close(player.spread_heat, 0.1)


def test_player_take_damage_heading_jitter_is_not_snapped_by_player_update() -> None:
    world = _scripted_world()
    player = world.players[0]
    player.pos = Vec2(100.0, 100.0)
    player.heading = 1.0
    player.move_speed = 2.0

    player_take_damage(make_step_runtime(world), player, 10.0, dt=0.1)
    target_heading = Vec2(1.0, 0.0).to_heading()
    step_player(world, player, player_input(move=Vec2(1.0, 0.0), aim=Vec2(200.0, 100.0)), 0.1)

    assert abs((player.heading % math.tau) - target_heading) > 1e-6
