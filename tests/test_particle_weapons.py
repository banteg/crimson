from __future__ import annotations

import math

from crimson.creatures.runtime import CreatureState
from crimson.gameplay import GameplayState, PlayerInput, PlayerState, player_fire_weapon, weapon_assign_player


class _FixedRng:
    def __init__(self, value: int) -> None:
        self._value = int(value)

    def rand(self) -> int:
        return int(self._value)


def test_particle_weapons_spawn_particles_and_use_fractional_ammo() -> None:
    cases = (
        (8, 0, 0.1),  # Plasma Rifle
        (15, 1, 0.05),  # HR Flamer
        (16, 2, 0.1),  # Mini-Rocket Swarmers
        (42, 8, 0.15),  # Rainbow Gun (slow particle)
    )

    for weapon_id, expected_style, ammo_cost in cases:
        state = GameplayState(rng=_FixedRng(0))
        player = PlayerState(index=0, pos_x=0.0, pos_y=0.0)
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

        assert state.projectiles.iter_active() == []
        assert state.secondary_projectiles.iter_active() == []

        assert math.isclose(float(player.ammo), start_ammo - ammo_cost, abs_tol=1e-9)
        assert state.weapon_shots_fired[0][weapon_id] == 1


def test_particle_hits_damage_creatures() -> None:
    state = GameplayState(rng=_FixedRng(0))
    player = PlayerState(index=0, pos_x=0.0, pos_y=0.0)
    player.aim_dir_x = 1.0
    player.aim_dir_y = 0.0
    player.spread_heat = 0.0

    weapon_assign_player(player, 8)
    player_fire_weapon(player, PlayerInput(fire_down=True, aim_x=200.0, aim_y=0.0), dt=0.016, state=state)

    creature = CreatureState()
    creature.active = True
    creature.hp = 100.0
    creature.x = 16.0
    creature.y = 0.0
    creature.size = 50.0
    creature.hitbox_size = 16.0

    state.particles.update(0.016, creatures=[creature])
    assert creature.hp < 100.0

    particles = [entry for entry in state.particles.entries if entry.active]
    assert particles
    assert particles[0].render_flag is False


def test_rainbow_gun_particle_kills_attached_target_on_expire() -> None:
    state = GameplayState(rng=_FixedRng(0))
    player = PlayerState(index=0, pos_x=0.0, pos_y=0.0)
    player.aim_dir_x = 1.0
    player.aim_dir_y = 0.0
    player.spread_heat = 0.0

    weapon_assign_player(player, 42)
    player_fire_weapon(player, PlayerInput(fire_down=True, aim_x=200.0, aim_y=0.0), dt=0.016, state=state)

    creature = CreatureState()
    creature.active = True
    creature.hp = 100.0
    creature.x = 16.0
    creature.y = 0.0
    creature.size = 50.0
    creature.hitbox_size = 16.0

    killed: list[tuple[int, int]] = []

    def _kill(creature_index: int, owner_id: int) -> None:
        killed.append((int(creature_index), int(owner_id)))

    state.particles.update(0.016, creatures=[creature], kill_creature=_kill)
    state.particles.update(2.0, creatures=[creature], kill_creature=_kill)

    assert killed == [(0, -1)]

