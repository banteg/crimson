from __future__ import annotations

from crimson.math_parity import f32, x87_pc24_add, x87_pc24_mul
from crimson.perks import PerkId
from crimson.player_damage import player_take_damage
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_tough_reloader_halves_damage_while_reloading() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2(), health=100.0)
    player.weapon.reload_active = True
    player.perk_counts[int(PerkId.TOUGH_RELOADER)] = 1

    applied = player_take_damage(state, player, 10.0, dt=0.1)

    assert_float_close(applied, 5.0)
    assert_float_close(player.health, 95.0)


def test_tough_reloader_sets_spread_heat_from_post_reload_damage_before_thick_skinned() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2(), health=100.0, spread_heat=0.1)
    player.weapon.reload_active = True
    player.perk_counts[int(PerkId.TOUGH_RELOADER)] = 1
    player.perk_counts[int(PerkId.THICK_SKINNED)] = 1

    _ = player_take_damage(state, player, 10.0, dt=0.1)

    assert player.spread_heat == x87_pc24_add(0.1, x87_pc24_mul(5.0, f32(0.01)))
