from __future__ import annotations

from grim.geom import Vec2

import math

from crimson.creatures.runtime import CreatureState
from crimson.gameplay import GameplayState, PlayerInput, PlayerState, player_fire_weapon, weapon_assign_player


class _FixedRng:
    def __init__(self, value: int) -> None:
        self._value = int(value)

    def rand(self) -> int:
        return int(self._value)


class _SequenceRng:
    def __init__(self, values: list[int]) -> None:
        self._values = [int(value) for value in values]
        self._idx = 0

    def rand(self) -> int:
        if not self._values:
            return 0
        if self._idx >= len(self._values):
            return int(self._values[-1])
        value = int(self._values[self._idx])
        self._idx += 1
        return value


def test_particle_weapons_spawn_particles_and_use_fractional_ammo() -> None:
    cases = (
        (8, 0, 0.1),  # Flamethrower
        (15, 1, 0.05),  # Blow Torch
        (16, 2, 0.1),  # HR Flamer
        (42, 8, 0.15),  # Bubblegun (slow particle)
    )

    for weapon_id, expected_style, ammo_cost in cases:
        state = GameplayState(rng=_FixedRng(1))
        player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
        player.aim_dir_x = 1.0
        player.aim_dir_y = 0.0
        player.spread_heat = 0.0

        weapon_assign_player(player, weapon_id)
        start_ammo = float(player.ammo)

        player_fire_weapon(player, PlayerInput(fire_down=True, aim_x=200.0, aim_y=0.0), dt=0.016, state=state)

        particles = [entry for entry in state.particles.entries if entry.active]
        assert len(particles) == 1
        assert int(particles[0].style_id) == expected_style
        assert int(particles[0].owner_id) == -1
        assert math.isclose(float(particles[0].angle), 0.0, abs_tol=1e-9)

        assert state.projectiles.iter_active() == []
        assert state.secondary_projectiles.iter_active() == []

        assert math.isclose(float(player.ammo), start_ammo - ammo_cost, abs_tol=1e-9)
        assert state.weapon_shots_fired[0][weapon_id] == 1


def test_flamethrower_particles_spawn_from_barrel_offset_muzzle() -> None:
    state = GameplayState(rng=_FixedRng(0))  # type: ignore[arg-type]
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    player.aim_dir_x = 0.0
    player.aim_dir_y = 1.0
    player.spread_heat = 0.0

    weapon_assign_player(player, 8)

    aim_x = 200.0
    aim_y = 0.0
    player_fire_weapon(player, PlayerInput(fire_down=True, aim_x=aim_x, aim_y=aim_y), dt=0.016, state=state)

    particles = [entry for entry in state.particles.entries if entry.active]
    assert len(particles) == 1
    particle = particles[0]

    dx = aim_x - float(player.pos.x)
    dy = aim_y - float(player.pos.y)
    aim_heading = math.atan2(dy, dx) + math.pi / 2.0
    muzzle_dir = (aim_heading - math.pi / 2.0) - 0.150915
    expected_x = float(player.pos.x) + math.cos(muzzle_dir) * 16.0
    expected_y = float(player.pos.y) + math.sin(muzzle_dir) * 16.0

    assert math.isclose(float(particle.pos.x), expected_x, abs_tol=1e-9)
    assert math.isclose(float(particle.pos.y), expected_y, abs_tol=1e-9)


def test_flamethrower_particle_angle_ignores_spread_heat_jitter() -> None:
    aim_x = 200.0
    aim_y = 0.0

    # Ensure the jittered aim point is significantly off-axis: dir_angle -> pi/2, mag -> near 1.0.
    # The third value is consumed by `spawn_particle` (spin).
    state = GameplayState(rng=_SequenceRng([128, 511, 0]))  # type: ignore[arg-type]
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    player.aim_dir_x = 1.0
    player.aim_dir_y = 0.0
    player.spread_heat = 0.48

    weapon_assign_player(player, 8)
    player_fire_weapon(player, PlayerInput(fire_down=True, aim_x=aim_x, aim_y=aim_y), dt=0.016, state=state)

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
    assert math.isclose(float(particle.angle), 0.0, abs_tol=1e-9)
    assert abs(float(particle.angle) - jittered_angle) > 0.1


def test_particle_hits_damage_creatures() -> None:
    state = GameplayState(rng=_FixedRng(0))
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    player.aim_dir_x = 1.0
    player.aim_dir_y = 0.0
    player.spread_heat = 0.0

    weapon_assign_player(player, 8)
    player_fire_weapon(player, PlayerInput(fire_down=True, aim_x=200.0, aim_y=0.0), dt=0.016, state=state)

    creature = CreatureState()
    creature.active = True
    creature.hp = 100.0
    creature.pos.x = 16.0
    creature.pos.y = 0.0
    creature.size = 50.0
    creature.hitbox_size = 16.0

    state.particles.update(0.016, creatures=[creature])
    assert creature.hp < 100.0

    particles = [entry for entry in state.particles.entries if entry.active]
    assert particles
    assert particles[0].render_flag is False


def test_bubblegun_particle_kills_attached_target_on_expire() -> None:
    state = GameplayState(rng=_FixedRng(0))
    player = PlayerState(index=0, pos=Vec2(0.0, 0.0))
    player.aim_dir_x = 1.0
    player.aim_dir_y = 0.0
    player.spread_heat = 0.0

    weapon_assign_player(player, 42)
    player_fire_weapon(player, PlayerInput(fire_down=True, aim_x=200.0, aim_y=0.0), dt=0.016, state=state)

    creature = CreatureState()
    creature.active = True
    creature.hp = 100.0
    creature.pos.x = 16.0
    creature.pos.y = 0.0
    creature.size = 50.0
    creature.hitbox_size = 16.0

    killed: list[tuple[int, int]] = []

    def _kill(creature_index: int, owner_id: int) -> None:
        killed.append((int(creature_index), int(owner_id)))

    state.particles.update(0.016, creatures=[creature], kill_creature=_kill)
    state.particles.update(2.0, creatures=[creature], kill_creature=_kill)

    assert killed == [(0, -1)]
