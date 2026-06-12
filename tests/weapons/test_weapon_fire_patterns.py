from __future__ import annotations

import math

import pytest

from crimson.gameplay import GameplayState
from crimson.math_parity import NATIVE_HALF_PI, f32
from crimson.projectiles.types import ProjectileTemplateId
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.weapon_runtime import (
    WeaponFireCtx,
    fire_weapon,
    weapon_assign_player,
)
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand, assert_float_close


def _active_projectiles(state: GameplayState) -> list[object]:
    return [entry for entry in state.projectiles.entries if entry.active]


def test_multi_plasma_fires_5_projectiles_with_fixed_spread() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2())
    player.aim_dir = Vec2(1.0, 0.0)
    player.spread_heat = 0.0

    weapon_assign_player(player, WeaponId.MULTI_PLASMA, state=state)
    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(200.0, 0.0)),
            dt=0.016,
            state=state,
        ),
    )

    spawned = _active_projectiles(state)
    assert len(spawned) == 5
    assert state.weapon_shots_fired[0][WeaponId.MULTI_PLASMA] == 5

    # Native heading: f32(atan2(pos - aim) - half_pi); one ulp below f32 pi/2
    # for a horizontal shot.
    shot_angle = float(f32(math.atan2(0.0, -1.0) - float(NATIVE_HALF_PI)))
    spread_small = math.pi / 10.0
    spread_large = math.pi / 6.0
    expected = (
        (shot_angle - spread_small, int(ProjectileTemplateId.PLASMA_RIFLE)),
        (shot_angle - spread_large, int(ProjectileTemplateId.PLASMA_MINIGUN)),
        (shot_angle, int(ProjectileTemplateId.PLASMA_RIFLE)),
        (shot_angle + spread_large, int(ProjectileTemplateId.PLASMA_MINIGUN)),
        (shot_angle + spread_small, int(ProjectileTemplateId.PLASMA_RIFLE)),
    )
    for proj, (angle, type_id) in zip(spawned, expected, strict=True):
        assert int(getattr(proj, "type_id", -1)) == type_id
        assert_float_close(float(getattr(proj, "angle", 0.0)), float(f32(angle)))


def test_plasma_shotgun_uses_0xff_jitter_and_random_speed_scale() -> None:
    # Use a value where (rand & 0xff) and (rand % 200 - 100) differ in sign, so we
    # catch the decompile-accurate mask behavior.
    state = GameplayState(rng=ScriptedCrand(255, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2())
    player.aim_dir = Vec2(1.0, 0.0)
    player.spread_heat = 0.0

    weapon_assign_player(player, WeaponId.PLASMA_SHOTGUN, state=state)
    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(200.0, 0.0)),
            dt=0.016,
            state=state,
        ),
    )

    spawned = _active_projectiles(state)
    assert len(spawned) == 14
    assert state.weapon_shots_fired[0][WeaponId.PLASMA_SHOTGUN] == 14

    # Native heading: f32(atan2(pos - aim) - half_pi); one ulp below f32 pi/2
    # for a horizontal shot.
    shot_angle = float(f32(math.atan2(0.0, -1.0) - float(NATIVE_HALF_PI)))
    expected_angle = float(f32(float(shot_angle) + (127.0 * 0.002)))
    expected_speed_scale = 1.0 + 55.0 * 0.01
    for proj in spawned:
        assert int(getattr(proj, "type_id", -1)) == int(ProjectileTemplateId.PLASMA_MINIGUN)
        assert_float_close(float(getattr(proj, "angle", 0.0)), expected_angle)
        assert_float_close(float(getattr(proj, "speed_scale", 0.0)), expected_speed_scale)


def test_plasma_shotgun_consumes_one_ammo_per_shot() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2())
    player.aim_dir = Vec2(1.0, 0.0)
    player.spread_heat = 0.0

    weapon_assign_player(player, WeaponId.PLASMA_SHOTGUN, state=state)
    start_ammo = float(player.weapon.ammo)

    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(200.0, 0.0)),
            dt=0.016,
            state=state,
        ),
    )
    assert_float_close(float(player.weapon.ammo), start_ammo - 1.0)


@pytest.mark.parametrize(
    ("weapon_id", "projectile_type_id", "expected_count", "jitter_scale", "expected_speed_scale"),
    [
        (WeaponId.JACKHAMMER, ProjectileTemplateId.SHOTGUN, 4, 0.0013, 1.0),
        (WeaponId.GAUSS_SHOTGUN, ProjectileTemplateId.GAUSS_GUN, 6, 0.002, 1.4),
        (WeaponId.ION_SHOTGUN, ProjectileTemplateId.ION_MINIGUN, 8, 0.0026, 1.4),
    ],
    ids=["jackhammer", "gauss-shotgun", "ion-shotgun"],
)
def test_shotgun_family_fires_expected_pellets(
    weapon_id: WeaponId,
    projectile_type_id: ProjectileTemplateId,
    expected_count: int,
    jitter_scale: float,
    expected_speed_scale: float,
) -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2())
    player.aim_dir = Vec2(1.0, 0.0)
    player.spread_heat = 0.0

    weapon_assign_player(player, WeaponId(weapon_id), state=state)
    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(200.0, 0.0)),
            dt=0.016,
            state=state,
        ),
    )

    spawned = _active_projectiles(state)
    assert len(spawned) == expected_count
    assert state.weapon_shots_fired[0][int(weapon_id)] == expected_count

    expected_angle = float(f32(float(f32(math.atan2(0.0, -1.0) - float(NATIVE_HALF_PI))) + (-100.0 * jitter_scale)))
    for proj in spawned:
        assert int(getattr(proj, "type_id", -1)) == int(projectile_type_id)
        assert_float_close(float(getattr(proj, "angle", 0.0)), expected_angle)
        assert_float_close(float(getattr(proj, "speed_scale", 0.0)), expected_speed_scale)
