from __future__ import annotations

from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapons import WEAPON_BY_ID, WeaponId
from grim.geom import Vec2
from tests.support.helpers import assert_float_close


def test_ammo_maniac_reassigns_weapons_and_increases_clip_size() -> None:
    state = GameplayState()
    owner_weapon = WeaponId.ASSAULT_RIFLE
    other_weapon = WeaponId.PISTOL

    owner = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=owner_weapon))
    other = PlayerState(index=1, pos=Vec2(), weapon=WeaponSlot(weapon_id=other_weapon))

    perk_apply(state, [owner, other], PerkId.AMMO_MANIAC)

    base_owner = int(WEAPON_BY_ID[owner_weapon].clip_size)
    extra_owner = max(1, int(float(base_owner) * 0.25))
    assert owner.weapon.clip_size == base_owner + extra_owner
    assert owner.weapon.ammo == owner.weapon.clip_size
    assert owner.weapon.reload_active is False
    assert_float_close(owner.weapon.reload_timer, 0.0)
    assert_float_close(owner.weapon.shot_cooldown, 0.0)

    base_other = int(WEAPON_BY_ID[other_weapon].clip_size)
    extra_other = max(1, int(float(base_other) * 0.25))
    assert other.weapon.clip_size == base_other + extra_other
    assert other.weapon.ammo == other.weapon.clip_size
    assert other.perk_counts[int(PerkId.AMMO_MANIAC)] == 1
