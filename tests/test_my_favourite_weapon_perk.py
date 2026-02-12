from __future__ import annotations

from grim.geom import Vec2

import pytest

from crimson.gameplay import GameplayState
from crimson.sim.state_types import PlayerState
from crimson.weapon_runtime import weapon_assign_player
from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply
from crimson.projectiles import ProjectileTypeId


def test_my_favourite_weapon_increases_clip_size() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(), weapon_id=int(ProjectileTypeId.PISTOL))
    weapon_assign_player(player, int(player.weapon_id))

    base_clip = int(player.clip_size)
    player.ammo = 5

    perk_apply(state, [player], PerkId.MY_FAVOURITE_WEAPON)

    assert player.clip_size == base_clip + 2
    assert player.ammo == 5

    weapon_assign_player(player, int(player.weapon_id))
    assert player.clip_size == base_clip + 2
    assert player.ammo == player.clip_size
    assert player.reload_timer == pytest.approx(0.0)
