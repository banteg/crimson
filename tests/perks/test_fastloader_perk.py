from __future__ import annotations

from crimson.math_parity import f32, x87_pc24_mul
from crimson.perks import PerkId
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapon_runtime import player_start_reload
from crimson.weapons import WEAPON_BY_ID, WeaponId
from grim.geom import Vec2
from tests.support.helpers import assert_float_close


def test_fastloader_scales_reload_timer() -> None:
    weapon_id = WeaponId.ASSAULT_RIFLE
    reload_time = float(WEAPON_BY_ID[weapon_id].reload_time)
    assert reload_time > 0.0

    base = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=weapon_id))
    perk = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=weapon_id))
    perk.perk_counts[int(PerkId.FASTLOADER)] = 1

    base_state = GameplayState()
    perk_state = GameplayState()

    player_start_reload(base, base_state)
    player_start_reload(perk, perk_state)

    assert base.weapon.reload_active is True
    assert perk.weapon.reload_active is True
    assert_float_close(base.weapon.reload_timer, reload_time)
    assert_float_close(perk.weapon.reload_timer, reload_time * 0.7)
    assert_float_close(perk.weapon.reload_timer_max, perk.weapon.reload_timer)


def test_fastloader_spills_before_weapon_power_up_scaling() -> None:
    weapon_id = WeaponId.PISTOL
    reload_time = f32(WEAPON_BY_ID[weapon_id].reload_time)
    player = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=weapon_id))
    player.perk_counts[int(PerkId.FASTLOADER)] = 1
    state = GameplayState()
    state.bonuses.weapon_power_up = 1.0

    player_start_reload(player, state)

    expected = x87_pc24_mul(x87_pc24_mul(reload_time, f32(0.7)), f32(0.6))
    assert player.weapon.reload_timer == expected
    assert player.weapon.reload_timer_max == expected
    assert expected != f32(float(reload_time) * 0.7 * 0.6)


def test_reload_uses_player_zero_perks_in_preserve_mode() -> None:
    weapon_id = WeaponId.ASSAULT_RIFLE
    reload_time = f32(WEAPON_BY_ID[weapon_id].reload_time)
    player0 = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=weapon_id))
    player1 = PlayerState(index=1, pos=Vec2(), weapon=WeaponSlot(weapon_id=weapon_id))
    player0.perk_counts[int(PerkId.FASTLOADER)] = 1
    state = GameplayState(preserve_bugs=True)

    player_start_reload(player1, state, players=[player0, player1])

    assert player1.weapon.reload_timer == x87_pc24_mul(reload_time, f32(0.7))

    player0.perk_counts[int(PerkId.AMMUNITION_WITHIN)] = 1
    player1.weapon.reload_timer = 0.25
    player_start_reload(player1, state, players=[player0, player1])

    assert player1.weapon.reload_timer == 0.25
