from __future__ import annotations

from crimson.math_parity import f32
from crimson.perks import PerkId
from tests.support.builders.session import make_world
from tests.support.factories import player_input, step_player
from tests.support.helpers import assert_float_close


def test_stationary_reloader_triples_reload_speed() -> None:
    base_world = make_world()
    base_player = base_world.players[0]
    base_player.weapon.reload_active = True
    base_player.weapon.reload_timer_max = 1.0
    base_player.weapon.reload_timer = 1.0

    perk_world = make_world()
    perk_player = perk_world.players[0]
    perk_world.state.perks[int(PerkId.STATIONARY_RELOADER)] = 1
    perk_player.weapon.reload_active = True
    perk_player.weapon.reload_timer_max = 1.0
    perk_player.weapon.reload_timer = 1.0

    step_player(base_world, base_player, player_input(), 0.1)
    step_player(perk_world, perk_player, player_input(), 0.1)

    assert_float_close(base_player.weapon.reload_timer, f32(0.9))
    assert_float_close(perk_player.weapon.reload_timer, f32(0.7))
