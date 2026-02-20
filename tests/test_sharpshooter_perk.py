from __future__ import annotations

from crimson.gameplay import (
    GameplayState,
    player_update,
)
from crimson.perks import PerkId
from crimson.projectiles import ProjectilePool, ProjectileTypeId
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.weapon_runtime import player_fire_weapon
from crimson.weapons import WEAPON_BY_ID
from grim.geom import Vec2
from tests.helpers import assert_float_close


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
    assert_float_close(player.spread_heat, 0.02)

    weapon = WEAPON_BY_ID[int(ProjectileTypeId.ASSAULT_RIFLE)]
    base_cooldown = float(weapon.shot_cooldown) if weapon.shot_cooldown is not None else 0.0
    expected_cooldown = base_cooldown * 1.05

    player_fire_weapon(player, PlayerInput(fire_down=True, aim=Vec2(200.0, 100.0)), 0.0, state)
    assert_float_close(player.shot_cooldown, expected_cooldown)
    assert_float_close(player.spread_heat, 0.02)
