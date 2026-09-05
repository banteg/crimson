from __future__ import annotations

from crimson.gameplay import player_update
from crimson.math_parity import f32
from crimson.perks import PerkId
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.support.helpers import assert_float_close


def test_stationary_reloader_triples_reload_speed() -> None:
    state = GameplayState()

    base_player = PlayerState(index=0, pos=Vec2(100.0, 100.0), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    base_player.weapon.reload_active = True
    base_player.weapon.reload_timer_max = 1.0
    base_player.weapon.reload_timer = 1.0

    perk_player = PlayerState(index=0, pos=Vec2(100.0, 100.0), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    perk_player.perk_counts[int(PerkId.STATIONARY_RELOADER)] = 1
    perk_player.weapon.reload_active = True
    perk_player.weapon.reload_timer_max = 1.0
    perk_player.weapon.reload_timer = 1.0

    player_update(base_player, PlayerInput(), dt=0.1, state=state)
    player_update(perk_player, PlayerInput(), dt=0.1, state=state)

    assert_float_close(base_player.weapon.reload_timer, f32(0.9))
    assert_float_close(perk_player.weapon.reload_timer, f32(0.7))
