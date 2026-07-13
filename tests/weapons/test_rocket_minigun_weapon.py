from __future__ import annotations

import math

from crimson.gameplay import GameplayState
from crimson.math_parity import NATIVE_HALF_PI, f32
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


def test_rocket_minigun_fires_full_clip_secondary_projectiles() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2())
    player.aim_dir = Vec2(1.0, 0.0)
    player.aim_heading = f32(math.atan2(0.0, -200.0) - NATIVE_HALF_PI)
    player.spread_heat = 0.0

    weapon_assign_player(player, WeaponId.MINI_ROCKET_SWARMERS, state=state)
    assert player.weapon.ammo == player.weapon.clip_size

    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(200.0, 0.0)),
            dt=0.016,
            state=state,
        ),
    )

    spawned = [entry for entry in state.secondary_projectiles.entries if entry.active]
    assert len(spawned) == player.weapon.clip_size
    assert player.weapon.ammo == 0
    assert player.weapon.reload_active is True

    assert state.weapon_shots_fired[0][WeaponId.MINI_ROCKET_SWARMERS] == player.weapon.clip_size

    # Native heading: f32(atan2(pos - aim) - half_pi); one ulp below f32 pi/2
    # for a horizontal shot.
    shot_angle = float(f32(math.atan2(0.0, -1.0) - float(NATIVE_HALF_PI)))
    spread = math.pi * (2.0 / 3.0)
    step = spread / float(player.weapon.clip_size - 1)
    expected0 = f32(float(shot_angle) - spread * 0.5)
    expected1 = f32(float(shot_angle) - spread * 0.5 + step)
    assert_float_close(spawned[0].angle, expected0)
    assert_float_close(spawned[1].angle, expected1)
