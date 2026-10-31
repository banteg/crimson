"""1.9.8 Fire Bullets: the weapon fires as normal and `projectile_spawn` adds a Fire Bullets shot to each projectile."""

from __future__ import annotations

import msgspec
import pytest

from crimson.cl_build import ClBuild
from crimson.game_modes import GameMode
from crimson.math_parity import f32
from crimson.projectiles.types import Projectile, ProjectileTemplateId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.run_init import initialize_run
from crimson.sim.run_spec import RunSpec
from crimson.sim.world_state import WorldState
from crimson.weapon_runtime import weapon_assign_player
from crimson.weapons import WEAPON_BY_ID, WeaponId
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand
from tests.support.factories import fire_player_weapon, player_input
from tests.support.helpers import assert_rng_progression


def _world(cl_build: ClBuild, *, preserve_bugs: bool = False) -> WorldState:
    spec = RunSpec(game_mode_id=GameMode.SURVIVAL, seed=7, preserve_bugs=preserve_bugs, cl_build=cl_build)
    return initialize_run(spec).session.world


def _fire(
    world: WorldState, weapon_id: WeaponId, *, fire_bullets_timer: float, fire_bullets_key_down: bool = False,
) -> tuple[list[Projectile], RecordingCrand]:
    """Fire one shot from a fresh `weapon_id` clip; return the active projectiles and the shot's recorded draws."""

    state = world.state
    player = world.players[0]
    weapon_assign_player(player, weapon_id, state=state)
    player.fire_bullets_timer = fire_bullets_timer
    state.rng = rng = RecordingCrand(Crand(123))
    aim = player.pos + Vec2(200.0, 0.0)
    fire_player_weapon(world, player, player_input(fire_down=True, aim=aim, fire_bullets_key_down=fire_bullets_key_down), 1 / 60)
    return [projectile for projectile in state.projectiles.entries if projectile.active], rng


@pytest.mark.parametrize("preserve_bugs", [False, True])
def test_shotgun_shot_gains_a_fire_bullets_shot_per_pellet(preserve_bugs: bool) -> None:
    plain_world = _world(ClBuild.V1_9_8, preserve_bugs=preserve_bugs)
    plain, plain_rng = _fire(plain_world, WeaponId.SHOTGUN, fire_bullets_timer=0.0)
    world = _world(ClBuild.V1_9_8, preserve_bugs=preserve_bugs)
    shot, rng = _fire(world, WeaponId.SHOTGUN, fire_bullets_timer=10.0)
    state = world.state
    player = world.players[0]

    # Each pellet's Fire Bullets shot takes the slot before it, at the same muzzle and angle.
    assert [p.type_id for p in shot] == [ProjectileTemplateId.FIRE_BULLETS, ProjectileTemplateId.SHOTGUN] * 12
    add_ons, pellets = shot[0::2], shot[1::2]
    assert [(p.pos, p.angle) for p in add_ons] == [(p.pos, p.angle) for p in pellets]
    assert [(p.pos, p.angle, p.speed_scale) for p in pellets] == [(p.pos, p.angle, p.speed_scale) for p in plain]
    # The pellet speed rolls land on the original shots, as `projectile_spawn` returns their slots.
    assert all(p.speed_scale == 1.0 for p in add_ons)
    assert state.shots_fired == 24
    assert state.weapon_shots_fired[0][WeaponId.SHOTGUN] == 12
    # The shotgun's own cadence, ammo and sound; the add-ons draw nothing.
    assert player.weapon.shot_cooldown == f32(WEAPON_BY_ID[WeaponId.SHOTGUN].shot_cooldown)
    assert player.weapon.ammo == player.weapon.clip_size - 1
    assert [r.caller for r in rng.records] == [r.caller for r in plain_rng.records]
    assert_rng_progression(
        rng,
        before_calls=0,
        before_state=Crand(123).state,
        expected_draws=plain_rng.calls,
        expected_after_state=plain_rng.state,
    )
    assert RngCallerStatic.PLAYER_UPDATE_SHOT_SFX in {r.caller for r in rng.records}
    assert state.sfx_queue == plain_world.state.sfx_queue


def test_last_shell_under_fire_bullets_starts_a_reload() -> None:
    world = _world(ClBuild.V1_9_8)
    player = world.players[0]
    weapon_assign_player(player, WeaponId.SHOTGUN, state=world.state)
    player.weapon.ammo = 1.0
    player.fire_bullets_timer = 10.0

    fire_player_weapon(world, player, player_input(fire_down=True, aim=player.pos + Vec2(200.0, 0.0)), 1 / 60)

    assert player.weapon.ammo == 0.0
    assert player.weapon.reload_active
    assert player.weapon.reload_timer == f32(WEAPON_BY_ID[WeaponId.SHOTGUN].reload_time)


@pytest.mark.parametrize("weapon_id", [WeaponId.FLAMETHROWER, WeaponId.ROCKET_LAUNCHER])
def test_weapons_without_projectile_spawn_get_no_fire_bullets(weapon_id: WeaponId) -> None:
    plain_world = _world(ClBuild.V1_9_8)
    plain, plain_rng = _fire(plain_world, weapon_id, fire_bullets_timer=0.0)
    world = _world(ClBuild.V1_9_8)
    shot, rng = _fire(world, weapon_id, fire_bullets_timer=10.0)

    assert shot == plain == []
    # The bonus changes nothing about the shot: same particles, rockets, ammo and draws.
    for name in ("particles", "secondary_projectiles"):
        assert msgspec.to_builtins(getattr(world.state, name).entries) == msgspec.to_builtins(
            getattr(plain_world.state, name).entries,
        )
    assert world.players[0].weapon.ammo == plain_world.players[0].weapon.ammo
    assert world.state.shots_fired == plain_world.state.shots_fired
    assert [r.caller for r in rng.records] == [r.caller for r in plain_rng.records]


@pytest.mark.parametrize(
    ("cl_build", "timer", "type_ids"),
    [
        (ClBuild.V1_9_93, 10.0, [ProjectileTemplateId.FIRE_BULLETS]),
        (ClBuild.V1_9_8, 0.0, [ProjectileTemplateId.PISTOL]),
    ],
)
def test_g_key_grants_fire_bullets_only_in_1_9_93(
    cl_build: ClBuild, timer: float, type_ids: list[ProjectileTemplateId],
) -> None:
    world = _world(cl_build, preserve_bugs=True)

    shot, _ = _fire(world, WeaponId.PISTOL, fire_bullets_timer=0.0, fire_bullets_key_down=True)

    assert world.players[0].fire_bullets_timer == timer
    assert [p.type_id for p in shot] == type_ids
