from __future__ import annotations

from crimson.gameplay import GameplayState
from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply
from crimson.projectiles import ProjectileTypeId
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapon_runtime import weapon_assign_player
from grim.geom import Vec2
from tests.helpers import assert_float_close


def test_my_favourite_weapon_increases_clip_size() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=int(ProjectileTypeId.PISTOL)))
    weapon_assign_player(player, int(player.weapon.weapon_id))

    base_clip = int(player.weapon.clip_size)
    player.weapon.ammo = 5

    perk_apply(state, [player], PerkId.MY_FAVOURITE_WEAPON)

    assert player.weapon.clip_size == base_clip + 2
    assert player.weapon.ammo == 5

    weapon_assign_player(player, int(player.weapon.weapon_id))
    assert player.weapon.clip_size == base_clip + 2
    assert player.weapon.ammo == player.weapon.clip_size
    assert_float_close(player.weapon.reload_timer, 0.0)
