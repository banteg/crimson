from __future__ import annotations

from grim.geom import Vec2

import pytest

from crimson.gameplay import GameplayState, PlayerState
from crimson.perks import PerkId
from crimson.perks.runtime.apply import perk_apply
from crimson.projectiles import ProjectileTypeId
from crimson.weapons import WEAPON_BY_ID


def test_ammo_maniac_reassigns_weapons_and_increases_clip_size() -> None:
    state = GameplayState()
    owner_weapon = int(ProjectileTypeId.ASSAULT_RIFLE)
    other_weapon = int(ProjectileTypeId.PISTOL)

    owner = PlayerState(index=0, pos=Vec2(), weapon_id=owner_weapon)
    other = PlayerState(index=1, pos=Vec2(), weapon_id=other_weapon)

    perk_apply(state, [owner, other], PerkId.AMMO_MANIAC)

    base_owner = int(WEAPON_BY_ID[owner_weapon].clip_size or 0)
    extra_owner = max(1, int(float(base_owner) * 0.25))
    assert owner.clip_size == base_owner + extra_owner
    assert owner.ammo == owner.clip_size
    assert owner.reload_active is False
    assert owner.reload_timer == pytest.approx(0.0)
    assert owner.shot_cooldown == pytest.approx(0.0)

    base_other = int(WEAPON_BY_ID[other_weapon].clip_size or 0)
    extra_other = max(1, int(float(base_other) * 0.25))
    assert other.clip_size == base_other + extra_other
    assert other.ammo == other.clip_size
    assert other.perk_counts[int(PerkId.AMMO_MANIAC)] == 1
