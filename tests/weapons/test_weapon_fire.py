from __future__ import annotations

from crimson.owner_ref import OwnerRef
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import WeaponSlot
from crimson.sim.world_state import WorldState
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import fire_player_weapon


def _fire_pistol(*, friendly_fire_enabled: bool) -> WorldState:
    world = make_world(player_count=2)
    world.state.friendly_fire_enabled = friendly_fire_enabled
    player = world.players[1]
    player.pos = Vec2(100.0, 100.0)
    player.weapon = WeaponSlot(weapon_id=WeaponId.PISTOL, clip_size=12, ammo=12)
    player.spread_heat = 0.0
    fire_player_weapon(world, player, PlayerInput(fire_down=True, aim=Vec2(200.0, 100.0)), 0.016)
    return world


def test_friendly_fire_enabled_primary_shots_can_hit_players() -> None:
    # Native encodes friendly fire in the owner id (-1 - player_index): with
    # the cvar enabled, primary player shots can hit the other player.
    world = _fire_pistol(friendly_fire_enabled=True)

    shots = [proj for proj in world.state.projectiles.entries if proj.active]
    assert shots
    assert all(proj.hits_players for proj in shots)
    assert all(proj.owner == OwnerRef.from_player(1) for proj in shots)


def test_friendly_fire_disabled_primary_shots_never_hit_players() -> None:
    world = _fire_pistol(friendly_fire_enabled=False)

    shots = [proj for proj in world.state.projectiles.entries if proj.active]
    assert shots
    assert not any(proj.hits_players for proj in shots)
    assert all(proj.owner == OwnerRef.from_local_player(0) for proj in shots)
