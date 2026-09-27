from __future__ import annotations

from crimson.math_parity import f32
from crimson.perks import PerkId
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import WeaponSlot
from crimson.sim.world_state import WorldState
from crimson.weapons import WeaponId
from tests.support.builders.session import make_world
from tests.support.factories import fire_player_weapon
from tests.support.helpers import assert_float_close


def _fire_once(world: WorldState) -> float:
    player = world.players[0]
    player.weapon = WeaponSlot(weapon_id=WeaponId.PISTOL, ammo=2)
    fire_player_weapon(world, player, PlayerInput(fire_down=True), 0.1)
    return float(player.weapon.shot_cooldown)


def test_fastshot_scales_shot_cooldown() -> None:
    base_cd = _fire_once(make_world())

    perk_world = make_world()
    perk_world.state.perks[int(PerkId.FASTSHOT)] = 1
    perk_cd = _fire_once(perk_world)

    assert_float_close(perk_cd, float(f32(float(base_cd) * 0.88)))
