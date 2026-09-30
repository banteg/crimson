from __future__ import annotations

from crimson.math_parity import f32, x87_pc24_mul
from crimson.perks import PerkId
from crimson.projectiles.types import ProjectileTemplateId
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import WeaponSlot
from crimson.weapons import WeaponId, weapon_entry_for_projectile_type_id
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import fire_player_weapon, step_player
from tests.support.helpers import assert_float_close


def test_sharpshooter_forces_spread_heat_and_slows_firing() -> None:
    world = make_world()
    player = world.players[0]
    player.pos = Vec2(100.0, 100.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE, clip_size=10, ammo=10)
    player.spread_heat = 0.48
    world.state.perks[int(PerkId.SHARPSHOOTER)] = 1

    step_player(world, player, PlayerInput(aim=Vec2(200.0, 100.0)), 0.1)
    assert_float_close(player.spread_heat, 0.02)

    weapon = weapon_entry_for_projectile_type_id(ProjectileTemplateId.ASSAULT_RIFLE)
    base_cooldown = float(weapon.shot_cooldown)
    # Native `shot_cooldown * 1.05f` at PC24.
    expected_cooldown = x87_pc24_mul(base_cooldown, f32(1.05))

    fire_player_weapon(world, player, PlayerInput(fire_down=True, aim=Vec2(200.0, 100.0)), 0.0)
    assert player.weapon.shot_cooldown == expected_cooldown
    assert_float_close(player.spread_heat, 0.02)
