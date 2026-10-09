from __future__ import annotations

from crimson.creatures.runtime import CreatureState
from crimson.creatures.spawn import CreatureTypeId
from crimson.sim.mode_updates import RushSpawnState, rush_mode_update
from crimson.weapons import WeaponId
from grim.rand import Crand, CrandLike
from tests.support.builders.session import make_world
from tests.support.helpers import assert_float_close


def _tick(rng: CrandLike, cooldown: float, *, run_elapsed_ms: int = 0) -> tuple[float, list[CreatureState]]:
    world = make_world()
    world.state.rng = rng
    spawn = RushSpawnState(spawn_cooldown_ms=cooldown)
    rush_mode_update(world, spawn, elapsed_ms=float(run_elapsed_ms), dt_ms=0.0)
    return spawn.spawn_cooldown_ms, [creature for creature in world.creatures.entries if creature.active]


def test_rush_mode_update_forces_assault_rifles_without_spawning_before_the_cooldown() -> None:
    world = make_world(player_count=2)
    world.state.rng = Crand(1)
    spawn = RushSpawnState(spawn_cooldown_ms=100.0)

    rush_mode_update(world, spawn, elapsed_ms=0.0, dt_ms=16.0)

    assert_float_close(spawn.spawn_cooldown_ms, 68.0)
    assert [(player.weapon.weapon_id, player.weapon.ammo) for player in world.players] == [
        (WeaponId.ASSAULT_RIFLE, 30.0),
        (WeaponId.ASSAULT_RIFLE, 30.0),
    ]
    assert not any(creature.active for creature in world.creatures.entries)
    assert world.state.rng.state == 1


def test_rush_mode_update_loops_when_cooldown_is_very_negative() -> None:
    rng = Crand(1)
    cooldown, spawns = _tick(rng, -501.0)

    assert_float_close(cooldown, 249.0)
    assert [c.type_id for c in spawns] == [CreatureTypeId.ALIEN, CreatureTypeId.SPIDER_SP1] * 3
    assert rng.state == 0xAEA69ED3
