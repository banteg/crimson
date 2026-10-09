from __future__ import annotations

import pytest

from crimson.sim.gameplay_state import GameplayState
from crimson.weapon_runtime import weapon_assign_player
from crimson.weapons import WeaponId
from grim.geom import Vec2
from grim.rand import Crand
from tests.support.builders.session import make_world
from tests.support.factories import fire_player_weapon, player_input


def _active_projectiles(state: GameplayState) -> list[object]:
    return [entry for entry in state.projectiles.entries if entry.active]


@pytest.mark.parametrize(
    "weapon_id",
    [
        WeaponId.SPIDER_PLASMA,
        WeaponId.FIRE_BULLETS,
    ],
)
def test_weapons_without_a_fire_branch_spend_the_shot_but_spawn_nothing(weapon_id: WeaponId) -> None:
    world = make_world()
    state = world.state
    state.rng = Crand(0x1234)
    player = world.players[0]
    player.pos = Vec2()
    player.aim_dir = Vec2(1.0, 0.0)
    weapon_assign_player(player, weapon_id, state=state)
    ammo = player.weapon.ammo

    fire_player_weapon(world, player, player_input(fire_down=True, aim=Vec2(200.0, 0.0)), 0.016)

    assert _active_projectiles(state) == []
    assert not any(entry.active for entry in state.secondary_projectiles.entries)
    assert not any(entry.active for entry in state.particles.entries)
    assert state.shots_fired == 0
    assert player.weapon.ammo == ammo - 1.0
    assert player.weapon.shot_cooldown > 0.0
