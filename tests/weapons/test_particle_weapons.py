from __future__ import annotations

import math

from crimson.creatures.runtime import CreatureState
from crimson.math_parity import NATIVE_HALF_PI, f32, native_fire_muzzle_pos, x87_pc24_sub
from crimson.owner_ref import OwnerRef
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.input import PlayerInput
from crimson.sim.world_state import WorldState
from crimson.weapon_runtime import weapon_assign_player
from crimson.weapons import WeaponId
from grim.geom import Vec2
from grim.rand import Crand
from tests.support.builders.session import make_world
from tests.support.factories import fire_player_weapon, make_creature_state, make_step_runtime, place_creatures
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_particle_weapons_spawn_particles_and_use_fractional_ammo() -> None:
    cases = (
        (WeaponId.FLAMETHROWER, 0, f32(0.1)),
        (WeaponId.BLOW_TORCH, 1, f32(0.05)),
        (WeaponId.HR_FLAMER, 2, f32(0.1)),
        (WeaponId.BUBBLEGUN, 8, f32(0.15)),
    )

    for weapon_id, expected_style, ammo_cost in cases:
        world = make_world()
        state = world.state
        state.rng = ScriptedCrand(1, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
        player = world.players[0]
        player.pos = Vec2()
        player.aim_dir = Vec2(1.0, 0.0)
        player.aim_heading = f32(math.atan2(0.0, -200.0) - NATIVE_HALF_PI)
        player.spread_heat = 0.0

        weapon_assign_player(player, weapon_id, state=state)
        start_ammo = float(player.weapon.ammo)

        fire_player_weapon(world, player, PlayerInput(fire_down=True, aim=Vec2(200.0, 0.0)), 0.016)

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
        # Native passes the unwrapped `heading - 1.5707964f`.
        expected_angle = x87_pc24_sub(expected_shot_angle, NATIVE_HALF_PI)
        assert_float_close(float(particles[0].angle), expected_angle)

        assert state.projectiles.iter_active() == []
        assert state.secondary_projectiles.iter_active() == []

        assert_float_close(float(player.weapon.ammo), x87_pc24_sub(start_ammo, ammo_cost))
        assert state.weapon_shots_fired[0][weapon_id] == 1


def test_flamethrower_particles_spawn_from_barrel_offset_muzzle() -> None:
    world = make_world()
    state = world.state
    state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    player = world.players[0]
    player.pos = Vec2()
    player.aim_dir = Vec2(0.0, 1.0)
    player.aim_heading = f32(math.atan2(0.0, -200.0) - NATIVE_HALF_PI)
    player.spread_heat = 0.0

    weapon_assign_player(player, WeaponId.FLAMETHROWER, state=state)

    aim_x = 200.0
    aim_y = 0.0
    fire_player_weapon(world, player, PlayerInput(fire_down=True, aim=Vec2(aim_x, aim_y)), 0.016)

    particles = [entry for entry in state.particles.entries if entry.active]
    assert len(particles) == 1
    particle = particles[0]

    expected_muzzle = native_fire_muzzle_pos(player.pos, player.aim_heading)

    assert_float_close(float(particle.pos.x), float(expected_muzzle.x))
    assert_float_close(float(particle.pos.y), float(expected_muzzle.y))


def test_flamethrower_particle_angle_ignores_spread_heat_jitter() -> None:
    aim_x = 200.0
    aim_y = 0.0

    world = make_world()
    state = world.state
    # Ensure the jittered aim point is significantly off-axis: dir_angle -> pi/2, mag -> near 1.0.
    # The particle pool keeps drawing from the world rng.
    state.rng = ScriptedCrand([128, 511], fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    player = world.players[0]
    player.pos = Vec2()
    player.aim_dir = Vec2(1.0, 0.0)
    player.aim_heading = f32(math.atan2(0.0, -200.0) - NATIVE_HALF_PI)
    player.spread_heat = 0.48

    weapon_assign_player(player, WeaponId.FLAMETHROWER, state=state)
    fire_player_weapon(world, player, PlayerInput(fire_down=True, aim=Vec2(aim_x, aim_y)), 0.016)

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
    expected_angle = x87_pc24_sub(player.aim_heading, NATIVE_HALF_PI)
    assert_float_close(float(particle.angle), expected_angle)
    assert abs(float(particle.angle) - jittered_angle) > 0.1


def _fire_at_creature(world: WorldState, weapon_id: WeaponId) -> CreatureState:
    state = world.state
    player = world.players[0]
    player.pos = Vec2()
    player.aim_dir = Vec2(1.0, 0.0)
    player.aim_heading = f32(math.atan2(0.0, -200.0) - NATIVE_HALF_PI)
    player.spread_heat = 0.0

    weapon_assign_player(player, weapon_id, state=state)
    fire_player_weapon(world, player, PlayerInput(fire_down=True, aim=Vec2(200.0, 0.0)), 0.016)

    return place_creatures(world, [make_creature_state(pos=Vec2(16.0, 0.0))])[0]


def test_particle_hits_damage_creatures() -> None:
    world = make_world()
    creature = _fire_at_creature(world, WeaponId.FLAMETHROWER)

    world.state.particles.update(
        0.016,
        step_runtime=make_step_runtime(world, dt=0.016),
        creatures=world.creatures.entries,
    )
    # Flamethrower particles deal intensity * 10 fire damage; intensity has decayed to 1 - 0.016 * 0.9.
    assert_float_close(creature.hp, f32(90.144))

    particles = [entry for entry in world.state.particles.entries if entry.active]
    assert particles
    assert particles[0].render_flag is False


def test_bubblegun_particle_kills_attached_target_on_expire() -> None:
    world = make_world()
    callers: list[int | None] = []
    rng = world.state.rng
    assert isinstance(rng, Crand)
    rng.set_trace_sink(lambda _before, _after, _value, caller: callers.append(caller))
    creature = _fire_at_creature(world, WeaponId.BUBBLEGUN)
    step_runtime = make_step_runtime(world)
    particles = world.state.particles

    particles.update(0.016, creatures=world.creatures.entries, step_runtime=step_runtime)
    particle = next(entry for entry in particles.entries if entry.active)
    attached_pos = particle.pos
    assert particle.target_id == 0
    assert not particle.render_flag

    creature.pos = Vec2(80.0, 40.0)
    particles.update(0.1, creatures=world.creatures.entries, step_runtime=step_runtime)
    assert particle.pos == attached_pos

    del callers[:]
    particles.update(2.0, creatures=world.creatures.entries, step_runtime=step_runtime)

    assert particle.target_id == 0
    assert [(death.index, death.owner) for death in step_runtime.deaths] == [(0, OwnerRef.from_player(0))]
    assert creature.active is False
    assert [request.position for request in step_runtime.sfx] == [Vec2(80.0, 40.0)]
    assert callers == [
        RngCallerStatic.PROJECTILE_UPDATE_PARTICLE_BUBBLEGUN_EXPIRY_SFX,
        RngCallerStatic.BONUS_TRY_SPAWN_ON_KILL_BASE_GATE,
    ]
