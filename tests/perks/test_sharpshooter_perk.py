from __future__ import annotations

from crimson.gameplay import player_update
from crimson.math_parity import f32
from crimson.perks import PerkId
from crimson.projectiles.runtime import ProjectilePool
from crimson.projectiles.types import ProjectileTemplateId
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapon_runtime import WeaponFireCtx, fire_weapon
from crimson.weapons import WeaponId, weapon_entry_for_projectile_type_id
from grim.geom import Vec2
from tests.support.helpers import assert_float_close


def test_sharpshooter_forces_spread_heat_and_slows_firing() -> None:
    pool = ProjectilePool(size=8)
    state = GameplayState(projectiles=pool)
    player = PlayerState(index=0,
    pos=Vec2(100.0, 100.0), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE, clip_size=10, ammo=10),
    spread_heat=0.48,)
    player.perk_counts[int(PerkId.SHARPSHOOTER)] = 1

    player_update(player, PlayerInput(aim=Vec2(200.0, 100.0)), 0.1, state)
    assert_float_close(player.spread_heat, 0.02)

    weapon = weapon_entry_for_projectile_type_id(ProjectileTemplateId.ASSAULT_RIFLE)
    base_cooldown = float(weapon.shot_cooldown)
    # Native stores the scaled cooldown as f32.
    expected_cooldown = float(f32(base_cooldown * 1.05))

    fire_weapon(WeaponFireCtx(player=player, input_state=PlayerInput(fire_down=True, aim=Vec2(200.0, 100.0)), dt=0.0, state=state))
    assert_float_close(player.weapon.shot_cooldown, expected_cooldown)
    assert_float_close(player.spread_heat, 0.02)
