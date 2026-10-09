from __future__ import annotations

import pytest

from crimson.math_parity import f32, x87_pc24_sub
from crimson.perks import PerkId
from crimson.sim.state_types import WeaponSlot
from crimson.sim.world_state import WorldState
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import fire_player_weapon, player_input
from tests.support.helpers import assert_float_close


def _reloading_world(*, weapon_id: WeaponId, ammo: float, experience: int) -> WorldState:
    world = make_world()
    world.state.perks[int(PerkId.REGRESSION_BULLETS)] = 1
    player = world.players[0]
    player.experience = experience
    player.weapon = WeaponSlot(weapon_id=weapon_id, ammo=ammo, reload_active=True, reload_timer=0.5)
    return world


def _fire(world: WorldState) -> None:
    fire_player_weapon(world, world.players[0], player_input(aim=Vec2(10.0, 0.0), fire_down=True), 0.016)


@pytest.mark.parametrize(
    ("experience", "remaining"),
    [(1000, 760), (16_777_217, 16_776_977)],
)
def test_regression_bullets_fires_during_reload_and_costs_experience(experience: int, remaining: int) -> None:
    world = _reloading_world(weapon_id=WeaponId.PISTOL, ammo=0, experience=experience)
    player = world.players[0]

    _fire(world)

    # Native FMUL then FSUBP round at PC=24: 240.000015... then 760.0,
    # before _ftol truncates. Host double arithmetic incorrectly gives 759.
    # FILD preserves integer XP exactly until the subtraction, even above 2**24.
    assert player.experience == remaining
    assert any(entry.active for entry in world.state.projectiles.entries)
    assert player.weapon.ammo == -1


def test_regression_bullets_fires_during_manual_reload_when_ammo_remaining() -> None:
    world = _reloading_world(weapon_id=WeaponId.PISTOL, ammo=5, experience=1000)
    player = world.players[0]

    _fire(world)

    # The PC=24 subtraction rounds to 760.0 before the truncating conversion.
    assert player.experience == 760
    assert any(entry.active for entry in world.state.projectiles.entries)
    assert player.weapon.ammo == 4


def test_regression_bullets_blocks_fire_when_experience_is_zero() -> None:
    world = _reloading_world(weapon_id=WeaponId.PISTOL, ammo=0, experience=0)

    _fire(world)

    assert not any(entry.active for entry in world.state.projectiles.entries)


@pytest.mark.parametrize(("experience", "remaining"), [(1000, 992), (2_147_483_647, 0)])
def test_regression_bullets_fire_weapon_fires_during_manual_reload_and_spends_ammo(
    experience: int,
    remaining: int,
) -> None:
    world = _reloading_world(weapon_id=WeaponId.FLAMETHROWER, ammo=5, experience=experience)
    player = world.players[0]

    _fire(world)

    # Cost is 2.0*4. At INT32_MAX, PC24 rounds to 2**31; EAX is negative and clamps to zero.
    assert player.experience == remaining
    assert any(entry.active for entry in world.state.particles.entries)
    # Native subtracts the float32 `0.1f` flamethrower cost at PC=24.
    assert_float_close(player.weapon.ammo, x87_pc24_sub(5.0, f32(0.1)))
