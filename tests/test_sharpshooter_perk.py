from __future__ import annotations

from grim.geom import Vec2

import pytest

from crimson.gameplay import GameplayState, PlayerInput, PlayerState, player_fire_weapon, player_update
from crimson.perks import PerkId
from crimson.projectiles import ProjectilePool, ProjectileTypeId
from crimson.weapons import WEAPON_BY_ID


def test_sharpshooter_forces_spread_heat_and_slows_firing() -> None:
    pool = ProjectilePool(size=8)
    state = GameplayState(projectiles=pool)
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        weapon_id=int(ProjectileTypeId.ASSAULT_RIFLE),
        clip_size=10,
        ammo=10,
        spread_heat=0.48,
    )
    player.perk_counts[int(PerkId.SHARPSHOOTER)] = 1

    player_update(player, PlayerInput(aim=Vec2(200.0, 100.0)), 0.1, state)
    assert player.spread_heat == pytest.approx(0.02)

    weapon = WEAPON_BY_ID[int(ProjectileTypeId.ASSAULT_RIFLE)]
    base_cooldown = float(weapon.shot_cooldown) if weapon.shot_cooldown is not None else 0.0
    expected_cooldown = base_cooldown * 1.05

    player_fire_weapon(player, PlayerInput(fire_down=True, aim=Vec2(200.0, 100.0)), 0.0, state)
    assert player.shot_cooldown == pytest.approx(expected_cooldown)
    assert player.spread_heat == pytest.approx(0.02)
