from __future__ import annotations

import math

from crimson.creatures.runtime import CreatureState
from crimson.math_parity import NATIVE_HALF_PI, f32, native_fire_muzzle_pos
from crimson.owner_ref import OwnerRef
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.weapon_runtime import (
    WeaponFireCtx,
    fire_weapon,
    weapon_assign_player,
)
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.support.factories import RecordingCreatureDamageRuntime
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_particle_weapons_spawn_particles_and_use_fractional_ammo() -> None:
    cases = (
        (WeaponId.FLAMETHROWER, 0, 0.1),
        (WeaponId.BLOW_TORCH, 1, 0.05),
        (WeaponId.HR_FLAMER, 2, 0.1),
        (WeaponId.BUBBLEGUN, 8, 0.15),
    )

    for weapon_id, expected_style, ammo_cost in cases:
        state = GameplayState(rng=ScriptedCrand(1, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
        player = PlayerState(index=0, pos=Vec2())
        player.aim_dir = Vec2(1.0, 0.0)
        player.aim_heading = f32(math.atan2(0.0, -200.0) - NATIVE_HALF_PI)
        player.spread_heat = 0.0

        weapon_assign_player(player, weapon_id, state=state)
        start_ammo = float(player.weapon.ammo)

        fire_weapon(
            WeaponFireCtx(
                player=player,
                input_state=PlayerInput(fire_down=True, aim=Vec2(200.0, 0.0)),
                dt=0.016,
                state=state,
            ),
        )

        particles = [entry for entry in state.particles.entries if entry.active]
        assert len(particles) == 1
        assert int(particles[0].style_id) == expected_style
        assert particles[0].owner == OwnerRef.from_player(0)
        if weapon_id == WeaponId.BUBBLEGUN:
            # Bubblegun particles use the jittered shot angle: native heading is
            # f32(atan2(pos - aim) - half_pi), one ulp below f32 pi/2 here.
            expected_shot_angle = float(f32(math.atan2(0.0, -200.0) - float(NATIVE_HALF_PI)))
        else:
            # Flamethrower-family particles use the raw aim heading.
            expected_shot_angle = float(player.aim_heading)
        expected_angle = Vec2.from_heading(expected_shot_angle).to_angle()
        assert_float_close(float(particles[0].angle), expected_angle)

        assert state.projectiles.iter_active() == []
        assert state.secondary_projectiles.iter_active() == []

        assert_float_close(float(player.weapon.ammo), start_ammo - ammo_cost)
        assert state.weapon_shots_fired[0][weapon_id] == 1


def test_flamethrower_particles_spawn_from_barrel_offset_muzzle() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2())
    player.aim_dir = Vec2(0.0, 1.0)
    player.aim_heading = f32(math.atan2(0.0, -200.0) - NATIVE_HALF_PI)
    player.spread_heat = 0.0

    weapon_assign_player(player, WeaponId.FLAMETHROWER, state=state)

    aim_x = 200.0
    aim_y = 0.0
    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(aim_x, aim_y)),
            dt=0.016,
            state=state,
        ),
    )

    particles = [entry for entry in state.particles.entries if entry.active]
    assert len(particles) == 1
    particle = particles[0]

    expected_muzzle = native_fire_muzzle_pos(player.pos, player.aim_heading)

    assert_float_close(float(particle.pos.x), float(expected_muzzle.x))
    assert_float_close(float(particle.pos.y), float(expected_muzzle.y))


def test_flamethrower_particle_angle_ignores_spread_heat_jitter() -> None:
    aim_x = 200.0
    aim_y = 0.0

    # Ensure the jittered aim point is significantly off-axis: dir_angle -> pi/2, mag -> near 1.0.
    # The third value is consumed by `spawn_particle` (spin).
    state = GameplayState(rng=ScriptedCrand([128, 511, 0], fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2())
    player.aim_dir = Vec2(1.0, 0.0)
    player.aim_heading = f32(math.atan2(0.0, -200.0) - NATIVE_HALF_PI)
    player.spread_heat = 0.48

    weapon_assign_player(player, WeaponId.FLAMETHROWER, state=state)
    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(aim_x, aim_y)),
            dt=0.016,
            state=state,
        ),
    )

    particles = [entry for entry in state.particles.entries if entry.active]
    assert len(particles) == 1
    particle = particles[0]

    # Recompute the actual jittered aim direction the weapon code would have used.
    dist = math.hypot(aim_x - float(player.pos.x), aim_y - float(player.pos.y))
    max_offset = dist * float(player.spread_heat) * 0.5
    dir_angle = float(128) * (math.tau / 512.0)
    mag = float(511) * (1.0 / 512.0)
    offset = max_offset * mag
    aim_jitter_x = aim_x + math.cos(dir_angle) * offset
    aim_jitter_y = aim_y + math.sin(dir_angle) * offset
    jittered_angle = math.atan2(aim_jitter_y - float(player.pos.y), aim_jitter_x - float(player.pos.x))

    assert jittered_angle > 0.1
    expected_angle = Vec2.from_heading(float(player.aim_heading)).to_angle()
    assert_float_close(float(particle.angle), expected_angle)
    assert abs(float(particle.angle) - jittered_angle) > 0.1


def test_particle_hits_damage_creatures() -> None:
    state = GameplayState(rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    player = PlayerState(index=0, pos=Vec2())
    player.aim_dir = Vec2(1.0, 0.0)
    player.aim_heading = f32(math.atan2(0.0, -200.0) - NATIVE_HALF_PI)
    player.spread_heat = 0.0

    weapon_assign_player(player, WeaponId.FLAMETHROWER, state=state)
    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(200.0, 0.0)),
            dt=0.016,
            state=state,
        ),
    )

    creature = CreatureState()
    creature.active = True
    creature.hp = 100.0
    creature.pos = Vec2(16.0, 0.0)
    creature.size = 50.0
    creature.lifecycle_stage = 16.0

    state.particles.update(
        0.016, creature_damage_runtime=RecordingCreatureDamageRuntime(creatures=[creature]), creatures=[creature],
    )
    assert creature.hp < 100.0

    particles = [entry for entry in state.particles.entries if entry.active]
    assert particles
    assert particles[0].render_flag is False


def test_bubblegun_particle_kills_attached_target_on_expire() -> None:
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    state = GameplayState(rng=rng)
    player = PlayerState(index=0, pos=Vec2())
    player.aim_dir = Vec2(1.0, 0.0)
    player.aim_heading = f32(math.atan2(0.0, -200.0) - NATIVE_HALF_PI)
    player.spread_heat = 0.0

    weapon_assign_player(player, WeaponId.BUBBLEGUN, state=state)
    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(200.0, 0.0)),
            dt=0.016,
            state=state,
        ),
    )

    creature = CreatureState()
    creature.active = True
    creature.hp = 100.0
    creature.pos = Vec2(16.0, 0.0)
    creature.size = 50.0
    creature.lifecycle_stage = 16.0

    damage_runtime = RecordingCreatureDamageRuntime(creatures=[creature])

    state.particles.update(0.016, creatures=[creature], creature_damage_runtime=damage_runtime)
    particle = next(entry for entry in state.particles.entries if entry.active)
    attached_pos = particle.pos
    assert particle.target_id == 0
    assert not particle.render_flag

    creature.pos = Vec2(80.0, 40.0)
    state.particles.update(0.1, creatures=[creature], creature_damage_runtime=damage_runtime)
    assert particle.pos == attached_pos

    state.particles.update(2.0, creatures=[creature], creature_damage_runtime=damage_runtime)

    assert damage_runtime.kills == [(0, OwnerRef.from_player(0))]
    assert particle.target_id == 0
    assert rng.records[-1].caller == RngCallerStatic.PROJECTILE_UPDATE_PARTICLE_BUBBLEGUN_EXPIRY_SFX
