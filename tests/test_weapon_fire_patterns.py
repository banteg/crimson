from __future__ import annotations

from grim.geom import Vec2

import math

from crimson.gameplay import GameplayState, PlayerInput, PlayerState, player_fire_weapon, weapon_assign_player
from crimson.projectiles import ProjectileTypeId


class _FixedRng:
    def __init__(self, value: int) -> None:
        self._value = int(value)

    def rand(self) -> int:
        return int(self._value)


def _active_projectiles(state: GameplayState) -> list[object]:
    return [entry for entry in state.projectiles.entries if entry.active]


def test_multi_plasma_fires_5_projectiles_with_fixed_spread() -> None:
    state = GameplayState(rng=_FixedRng(0))
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    player.aim_dir_x = 1.0
    player.aim_dir_y = 0.0
    player.spread_heat = 0.0

    weapon_assign_player(player, 10)
    player_fire_weapon(player, PlayerInput(fire_down=True, aim_x=200.0, aim_y=0.0), dt=0.016, state=state)

    spawned = _active_projectiles(state)
    assert len(spawned) == 5
    assert state.weapon_shots_fired[0][10] == 5

    shot_angle = math.pi / 2.0
    spread_small = math.pi / 10.0
    spread_large = math.pi / 6.0
    expected = (
        (shot_angle - spread_small, int(ProjectileTypeId.PLASMA_RIFLE)),
        (shot_angle - spread_large, int(ProjectileTypeId.PLASMA_MINIGUN)),
        (shot_angle, int(ProjectileTypeId.PLASMA_RIFLE)),
        (shot_angle + spread_large, int(ProjectileTypeId.PLASMA_MINIGUN)),
        (shot_angle + spread_small, int(ProjectileTypeId.PLASMA_RIFLE)),
    )
    for proj, (angle, type_id) in zip(spawned, expected, strict=True):
        assert int(getattr(proj, "type_id", -1)) == type_id
        assert math.isclose(float(getattr(proj, "angle", 0.0)), angle, abs_tol=1e-9)


def test_plasma_shotgun_uses_0xff_jitter_and_random_speed_scale() -> None:
    # Use a value where (rand & 0xff) and (rand % 200 - 100) differ in sign, so we
    # catch the decompile-accurate mask behavior.
    state = GameplayState(rng=_FixedRng(255))
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    player.aim_dir_x = 1.0
    player.aim_dir_y = 0.0
    player.spread_heat = 0.0

    weapon_assign_player(player, 14)
    player_fire_weapon(player, PlayerInput(fire_down=True, aim_x=200.0, aim_y=0.0), dt=0.016, state=state)

    spawned = _active_projectiles(state)
    assert len(spawned) == 14
    assert state.weapon_shots_fired[0][14] == 14

    shot_angle = math.pi / 2.0
    expected_angle = shot_angle + (127.0 * 0.002)
    expected_speed_scale = 1.0 + 55.0 * 0.01
    for proj in spawned:
        assert int(getattr(proj, "type_id", -1)) == int(ProjectileTypeId.PLASMA_MINIGUN)
        assert math.isclose(float(getattr(proj, "angle", 0.0)), expected_angle, abs_tol=1e-9)
        assert math.isclose(float(getattr(proj, "speed_scale", 0.0)), expected_speed_scale, abs_tol=1e-9)


def test_plasma_shotgun_consumes_one_ammo_per_shot() -> None:
    state = GameplayState(rng=_FixedRng(0))
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    player.aim_dir_x = 1.0
    player.aim_dir_y = 0.0
    player.spread_heat = 0.0

    weapon_assign_player(player, 14)
    start_ammo = float(player.ammo)

    player_fire_weapon(player, PlayerInput(fire_down=True, aim_x=200.0, aim_y=0.0), dt=0.016, state=state)
    assert math.isclose(float(player.ammo), start_ammo - 1.0, abs_tol=1e-9)


def test_jackhammer_spawns_4_shotgun_pellets_with_jitter_and_speed_scale() -> None:
    state = GameplayState(rng=_FixedRng(0))
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    player.aim_dir_x = 1.0
    player.aim_dir_y = 0.0
    player.spread_heat = 0.0

    weapon_assign_player(player, 20)
    player_fire_weapon(player, PlayerInput(fire_down=True, aim_x=200.0, aim_y=0.0), dt=0.016, state=state)

    spawned = _active_projectiles(state)
    assert len(spawned) == 4
    assert state.weapon_shots_fired[0][20] == 4

    expected_angle = math.pi / 2.0 + (-100.0 * 0.0013)
    for proj in spawned:
        assert int(getattr(proj, "type_id", -1)) == int(ProjectileTypeId.SHOTGUN)
        assert math.isclose(float(getattr(proj, "angle", 0.0)), expected_angle, abs_tol=1e-9)
        assert math.isclose(float(getattr(proj, "speed_scale", 0.0)), 1.0, abs_tol=1e-9)


def test_gauss_shotgun_fires_6_gauss_pellets() -> None:
    state = GameplayState(rng=_FixedRng(0))
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    player.aim_dir_x = 1.0
    player.aim_dir_y = 0.0
    player.spread_heat = 0.0

    weapon_assign_player(player, 30)
    player_fire_weapon(player, PlayerInput(fire_down=True, aim_x=200.0, aim_y=0.0), dt=0.016, state=state)

    spawned = _active_projectiles(state)
    assert len(spawned) == 6
    assert state.weapon_shots_fired[0][30] == 6

    expected_angle = math.pi / 2.0 + (-100.0 * 0.002)
    for proj in spawned:
        assert int(getattr(proj, "type_id", -1)) == int(ProjectileTypeId.GAUSS_GUN)
        assert math.isclose(float(getattr(proj, "angle", 0.0)), expected_angle, abs_tol=1e-9)
        assert math.isclose(float(getattr(proj, "speed_scale", 0.0)), 1.4, abs_tol=1e-9)


def test_ion_shotgun_fires_8_ion_minigun_pellets() -> None:
    state = GameplayState(rng=_FixedRng(0))
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    player.aim_dir_x = 1.0
    player.aim_dir_y = 0.0
    player.spread_heat = 0.0

    weapon_assign_player(player, 31)
    player_fire_weapon(player, PlayerInput(fire_down=True, aim_x=200.0, aim_y=0.0), dt=0.016, state=state)

    spawned = _active_projectiles(state)
    assert len(spawned) == 8
    assert state.weapon_shots_fired[0][31] == 8

    expected_angle = math.pi / 2.0 + (-100.0 * 0.0026)
    for proj in spawned:
        assert int(getattr(proj, "type_id", -1)) == int(ProjectileTypeId.ION_MINIGUN)
        assert math.isclose(float(getattr(proj, "angle", 0.0)), expected_angle, abs_tol=1e-9)
        assert math.isclose(float(getattr(proj, "speed_scale", 0.0)), 1.4, abs_tol=1e-9)
