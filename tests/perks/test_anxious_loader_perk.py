from __future__ import annotations

from crimson.math_parity import f32
from crimson.perks import PerkId
from crimson.sim.input import PlayerInput
from tests.support.builders.session import make_world
from tests.support.factories import step_player
from tests.support.helpers import assert_float_close


def test_anxious_loader_reduces_reload_timer_on_fire_press() -> None:
    base_world = make_world()
    base_player = base_world.players[0]
    base_player.weapon.reload_active = True
    base_player.weapon.reload_timer_max = 1.0
    base_player.weapon.reload_timer = 1.0

    perk_world = make_world()
    perk_player = perk_world.players[0]
    perk_world.state.perks[int(PerkId.ANXIOUS_LOADER)] = 1
    perk_player.weapon.reload_active = True
    perk_player.weapon.reload_timer_max = 1.0
    perk_player.weapon.reload_timer = 1.0

    input_state = PlayerInput(fire_pressed=True)
    step_player(base_world, base_player, input_state, 0.1)
    step_player(perk_world, perk_player, input_state, 0.1)

    expected_base_timer = f32(f32(1.0) - f32(0.1))
    expected_perk_timer = f32(f32(f32(1.0) - 0.05) - f32(0.1))
    assert_float_close(base_player.weapon.reload_timer, expected_base_timer)
    assert_float_close(perk_player.weapon.reload_timer, expected_perk_timer)
