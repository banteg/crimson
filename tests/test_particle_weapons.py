from __future__ import annotations

import math

from crimson.creatures.runtime import CreatureState
from crimson.gameplay import GameplayState
from crimson.owner_ref import OwnerRef
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.weapon_runtime import (
    player_fire_weapon,
    weapon_assign_player,
)
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.helpers import MockCrand, assert_float_close


def test_particle_weapons_spawn_particles_and_use_fractional_ammo() -> None:
    cases = (
        (int(WeaponId.FLAMETHROWER), 0, 0.1),
        (int(WeaponId.BLOW_TORCH), 1, 0.05),
        (int(WeaponId.HR_FLAMER), 2, 0.1),
        (int(WeaponId.BUBBLEGUN), 8, 0.15),
    )

    for weapon_id, expected_style, ammo_cost in cases:
        state = GameplayState(rng=MockCrand(1))
        player = PlayerState(index=0, pos=Vec2())
        player.aim_dir = Vec2(1.0, 0.0)
        player.spread_heat = 0.0

        weapon_assign_player(player, weapon_id)
        start_ammo = float(player.ammo)

        player_fire_weapon(player, PlayerInput(fire_down=True, aim=Vec2(200.0, 0.0)), dt=0.016, state=state)

        particles = [entry for entry in state.particles.entries if entry.active]
        assert len(particles) == 1
        assert int(particles[0].style_id) == expected_style
        assert int(particles[0].owner_id) == -1
        assert_float_close(float(particles[0].angle), 0.0)

        assert state.projectiles.iter_active() == []
        assert state.secondary_projectiles.iter_active() == []

        assert_float_close(float(player.ammo), start_ammo - ammo_cost)
        assert state.weapon_shots_fired[0][weapon_id] == 1


def test_flamethrower_particles_spawn_from_barrel_offset_muzzle() -> None:
    state = GameplayState(rng=MockCrand(0))
    player = PlayerState(index=0, pos=Vec2())
    player.aim_dir = Vec2(0.0, 1.0)
    player.spread_heat = 0.0

    weapon_assign_player(player, int(WeaponId.FLAMETHROWER))

    aim_x = 200.0
    aim_y = 0.0
    player_fire_weapon(player, PlayerInput(fire_down=True, aim=Vec2(aim_x, aim_y)), dt=0.016, state=state)

    particles = [entry for entry in state.particles.entries if entry.active]
    assert len(particles) == 1
    particle = particles[0]

    dx = aim_x - float(player.pos.x)
    dy = aim_y - float(player.pos.y)
    aim_heading = math.atan2(dy, dx) + math.pi / 2.0
    muzzle_dir = (aim_heading - math.pi / 2.0) - 0.150915
    expected_x = float(player.pos.x) + math.cos(muzzle_dir) * 16.0
    expected_y = float(player.pos.y) + math.sin(muzzle_dir) * 16.0

    assert_float_close(float(particle.pos.x), expected_x)
    assert_float_close(float(particle.pos.y), expected_y)


def test_flamethrower_particle_angle_ignores_spread_heat_jitter() -> None:
    aim_x = 200.0
    aim_y = 0.0

    # Ensure the jittered aim point is significantly off-axis: dir_angle -> pi/2, mag -> near 1.0.
    # The third value is consumed by `spawn_particle` (spin).
    state = GameplayState(rng=MockCrand([128, 511, 0], fallback="repeat_last"))
    player = PlayerState(index=0, pos=Vec2())
    player.aim_dir = Vec2(1.0, 0.0)
    player.spread_heat = 0.48

    weapon_assign_player(player, int(WeaponId.FLAMETHROWER))
    player_fire_weapon(player, PlayerInput(fire_down=True, aim=Vec2(aim_x, aim_y)), dt=0.016, state=state)

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
    assert_float_close(float(particle.angle), 0.0)
    assert abs(float(particle.angle) - jittered_angle) > 0.1


def test_particle_hits_damage_creatures() -> None:
    state = GameplayState(rng=MockCrand(0))
    player = PlayerState(index=0, pos=Vec2())
    player.aim_dir = Vec2(1.0, 0.0)
    player.spread_heat = 0.0

    weapon_assign_player(player, int(WeaponId.FLAMETHROWER))
    player_fire_weapon(player, PlayerInput(fire_down=True, aim=Vec2(200.0, 0.0)), dt=0.016, state=state)

    creature = CreatureState()
    creature.active = True
    creature.hp = 100.0
    creature.pos = Vec2(16.0, 0.0)
    creature.size = 50.0
    creature.lifecycle_stage = 16.0

    state.particles.update(0.016, creatures=[creature])
    assert creature.hp < 100.0

    particles = [entry for entry in state.particles.entries if entry.active]
    assert particles
    assert particles[0].render_flag is False


def test_bubblegun_particle_kills_attached_target_on_expire() -> None:
    state = GameplayState(rng=MockCrand(0))
    player = PlayerState(index=0, pos=Vec2())
    player.aim_dir = Vec2(1.0, 0.0)
    player.spread_heat = 0.0

    weapon_assign_player(player, int(WeaponId.BUBBLEGUN))
    player_fire_weapon(player, PlayerInput(fire_down=True, aim=Vec2(200.0, 0.0)), dt=0.016, state=state)

    creature = CreatureState()
    creature.active = True
    creature.hp = 100.0
    creature.pos = Vec2(16.0, 0.0)
    creature.size = 50.0
    creature.lifecycle_stage = 16.0

    killed: list[tuple[int, int]] = []

    def _kill(creature_index: int, owner: OwnerRef) -> None:
        killed.append((int(creature_index), owner.to_legacy()))

    state.particles.update(0.016, creatures=[creature], kill_creature=_kill)
    state.particles.update(2.0, creatures=[creature], kill_creature=_kill)

    assert killed == [(0, -1)]
