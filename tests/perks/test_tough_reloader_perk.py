from __future__ import annotations

from crimson.math_parity import f32, x87_pc24_add, x87_pc24_mul
from crimson.perks import PerkId
from crimson.player_damage import player_take_damage
from tests.support.builders.session import make_world
from tests.support.factories import make_step_runtime
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_tough_reloader_halves_damage_while_reloading() -> None:
    world = make_world()
    state = world.state
    state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    player = world.players[0]
    player.weapon.reload_active = True
    state.perks[int(PerkId.TOUGH_RELOADER)] = 1

    applied = player_take_damage(make_step_runtime(world), player, 10.0, dt=0.1)

    assert_float_close(applied, 5.0)
    assert_float_close(player.health, 95.0)


def test_tough_reloader_sets_spread_heat_from_post_reload_damage_before_thick_skinned() -> None:
    world = make_world()
    state = world.state
    state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    player = world.players[0]
    player.spread_heat = 0.1
    player.weapon.reload_active = True
    state.perks[int(PerkId.TOUGH_RELOADER)] = 1
    state.perks[int(PerkId.THICK_SKINNED)] = 1

    _ = player_take_damage(make_step_runtime(world), player, 10.0, dt=0.1)

    assert player.spread_heat == x87_pc24_add(0.1, x87_pc24_mul(5.0, f32(0.01)))
