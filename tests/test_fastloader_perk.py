from __future__ import annotations

from crimson.gameplay import GameplayState
from crimson.perks import PerkId
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapon_runtime import player_start_reload
from crimson.weapons import WEAPON_BY_ID, WeaponId
from grim.geom import Vec2
from tests.helpers import assert_float_close


def test_fastloader_scales_reload_timer() -> None:
    weapon_id = WeaponId.ASSAULT_RIFLE
    reload_time = float(WEAPON_BY_ID[int(weapon_id)].reload_time or 0.0)
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
