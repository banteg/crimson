from __future__ import annotations

from dataclasses import dataclass
import math

from crimson.gameplay import GameplayState, PlayerState
from crimson.effects import FxQueue
from crimson.projectiles import ProjectilePool, SecondaryProjectilePool
from crimson.projectiles import ProjectileTypeId


@dataclass(slots=True)
class _Creature:
    x: float
    y: float
    hp: float


def _fixed_rng(value: int):
    def _rng() -> int:
        return value

    return _rng


def _expected_damage(dist: float, damage_scale: float = 1.0) -> float:
    if dist < 50.0:
        dist = 50.0
    return ((100.0 / dist) * damage_scale * 30.0 + 10.0) * 0.95


def test_projectile_pool_keeps_flight_timer_when_in_bounds() -> None:
    pool = ProjectilePool(size=1)
    idx = pool.spawn(pos_x=0.0, pos_y=0.0, angle=math.pi / 2.0, type_id=4, owner_id=-100)
    proj = pool.entries[idx]
    assert proj.active
    assert proj.life_timer == 0.4

    pool.update_demo(
        0.1,
        [],
        world_size=1024.0,
        speed_by_type={4: 100.0},
        damage_by_type={},
    )
    assert proj.active
    assert proj.life_timer == 0.4
    assert math.isclose(proj.pos_x, 10.0, abs_tol=1e-9)


def test_projectile_pool_update_moves_by_projectile_meta() -> None:
    pool = ProjectilePool(size=1)
    idx = pool.spawn(
        pos_x=0.0,
        pos_y=0.0,
        angle=math.pi / 2.0,
        type_id=4,
        owner_id=-100,
        base_damage=15.0,
    )
    proj = pool.entries[idx]

    pool.update(0.1, [], world_size=1024.0, damage_scale_by_type={4: 1.0})

    assert proj.active
    assert proj.life_timer == 0.4
    assert math.isclose(proj.pos_x, 30.0, abs_tol=1e-9)


def test_projectile_pool_update_applies_distance_scaled_damage() -> None:
    pool = ProjectilePool(size=1)
    pool.spawn(
        pos_x=0.0,
        pos_y=0.0,
        angle=math.pi / 2.0,
        type_id=4,
        owner_id=-100,
        base_damage=15.0,
    )

    creatures = [_Creature(x=41.1428575, y=0.0, hp=100.0)]
    hits = pool.update(0.1, creatures, world_size=1024.0, damage_scale_by_type={4: 1.0})

    assert hits == [(4, 0.0, 0.0, 30.0, 0.0, 41.1428575, 0.0)]
    assert math.isclose(creatures[0].hp, 33.5, abs_tol=1e-9)


def test_projectile_pool_update_applies_rng_jitter_to_hit_position() -> None:
    pool = ProjectilePool(size=1)
    idx = pool.spawn(
        pos_x=0.0,
        pos_y=0.0,
        angle=math.pi / 2.0,
        type_id=4,
        owner_id=-100,
        base_damage=30.0,
    )
    creatures = [_Creature(x=71.1428574, y=0.0, hp=100.0)]

    hits = pool.update(
        0.1,
        creatures,
        world_size=1024.0,
        damage_scale_by_type={4: 1.0},
        rng=_fixed_rng(2),
    )

    assert hits == [(4, 0.0, 0.0, 60.0, 0.0, 71.1428574, 0.0)]
    proj = pool.entries[idx]
    assert math.isclose(proj.pos_x, 62.0, abs_tol=1e-9)
    assert proj.life_timer == 0.25

    expected_damage = _expected_damage(62.0, 1.0)
    assert math.isclose(creatures[0].hp, 100.0 - expected_damage, abs_tol=1e-6)


def test_projectile_pool_update_type_0x0b_does_not_splash_damage() -> None:
    pool = ProjectilePool(size=1)
    pool.spawn(
        pos_x=0.0,
        pos_y=0.0,
        angle=math.pi / 2.0,
        type_id=0x0B,
        owner_id=-100,
        base_damage=30.0,
    )
    creatures = [
        _Creature(x=71.1428574, y=0.0, hp=100.0),
        _Creature(x=100.0, y=0.0, hp=100.0),
        _Creature(x=160.0, y=0.0, hp=100.0),
        _Creature(x=220.0, y=0.0, hp=100.0),
    ]

    hits = pool.update(
        0.1,
        creatures,
        world_size=1024.0,
        damage_scale_by_type={0x0B: 1.0},
        rng=_fixed_rng(0),
    )

    assert hits == [(0x0B, 0.0, 0.0, 60.0, 0.0, 71.1428574, 0.0)]
    assert math.isclose(creatures[0].hp, 100.0 - _expected_damage(60.0), abs_tol=1e-6)
    assert math.isclose(creatures[1].hp, 100.0, abs_tol=1e-9)
    assert math.isclose(creatures[2].hp, 100.0, abs_tol=1e-9)
    assert math.isclose(creatures[3].hp, 100.0, abs_tol=1e-9)


def test_projectile_pool_update_type_0x0b_does_not_splash_nearby_creatures() -> None:
    pool = ProjectilePool(size=1)
    pool.spawn(
        pos_x=0.0,
        pos_y=0.0,
        angle=math.pi / 2.0,
        type_id=0x0B,
        owner_id=-100,
        base_damage=15.0,
    )
    creatures = [
        _Creature(x=30.0, y=0.0, hp=100.0),
        _Creature(x=70.0, y=0.0, hp=100.0),
        _Creature(x=200.0, y=0.0, hp=100.0),
    ]

    pool.update(0.1, creatures, world_size=1024.0, damage_scale_by_type={0x0B: 1.0})

    assert creatures[0].hp < 100.0
    assert math.isclose(creatures[1].hp, 100.0, abs_tol=1e-9)
    assert math.isclose(creatures[2].hp, 100.0, abs_tol=1e-9)


def test_projectile_pool_update_ion_minigun_linger_deals_aoe_damage() -> None:
    pool = ProjectilePool(size=1)
    pool.spawn(
        pos_x=0.0,
        pos_y=0.0,
        angle=math.pi / 2.0,
        type_id=0x16,
        owner_id=-100,
        base_damage=20.0,
    )
    creatures = [_Creature(x=40.0, y=0.0, hp=200.0)]

    pool.update(0.1, creatures, world_size=1024.0, damage_scale_by_type={0x16: 1.4})
    hp_after_hit = creatures[0].hp

    pool.update(0.1, creatures, world_size=1024.0, damage_scale_by_type={0x16: 1.4})
    assert creatures[0].hp < hp_after_hit


def test_projectile_pool_update_ion_hit_spawns_ring_and_burst_effects() -> None:
    state = GameplayState()
    state.projectiles.spawn(
        pos_x=0.0,
        pos_y=0.0,
        angle=math.pi / 2.0,
        type_id=int(ProjectileTypeId.ION_MINIGUN),
        owner_id=-100,
        base_damage=20.0,
    )
    creatures = [_Creature(x=10.0, y=0.0, hp=100.0)]

    state.projectiles.update(
        0.1,
        creatures,
        world_size=1024.0,
        damage_scale_by_type={int(ProjectileTypeId.ION_MINIGUN): 1.0},
        detail_preset=5,
        rng=_fixed_rng(0),
        runtime_state=state,
        players=[PlayerState(index=0, pos_x=0.0, pos_y=0.0)],
    )

    active = state.effects.iter_active()
    rings = [entry for entry in active if int(entry.effect_id) == 1]
    bursts = [entry for entry in active if int(entry.effect_id) == 0]
    assert len(rings) == 1
    assert len(bursts) == 20

    ring = rings[0]
    assert math.isclose(float(ring.pos_x), 10.0, abs_tol=1e-9)
    assert math.isclose(float(ring.pos_y), 0.0, abs_tol=1e-9)
    assert math.isclose(float(ring.half_width), 4.0, abs_tol=1e-9)
    assert math.isclose(float(ring.half_height), 4.0, abs_tol=1e-9)
    assert math.isclose(float(ring.scale_step), 67.5, abs_tol=1e-9)
    assert math.isclose(float(ring.lifetime), 0.08, abs_tol=1e-9)

    burst = bursts[0]
    assert math.isclose(float(burst.half_width), 20.48, abs_tol=1e-6)
    assert math.isclose(float(burst.half_height), 20.48, abs_tol=1e-6)
    assert math.isclose(float(burst.lifetime), 0.448, abs_tol=1e-6)


def test_projectile_pool_emits_hit_event_and_enters_hit_state() -> None:
    pool = ProjectilePool(size=1)
    idx = pool.spawn(pos_x=0.0, pos_y=0.0, angle=math.pi / 2.0, type_id=4, owner_id=-100)
    proj = pool.entries[idx]

    creatures = [_Creature(x=10.0, y=0.0, hp=100.0)]
    hits = pool.update_demo(
        0.1,
        creatures,
        world_size=1024.0,
        speed_by_type={4: 100.0},
        damage_by_type={4: 18.0},
    )

    assert hits == [(4, 0.0, 0.0, 10.0, 0.0, 10.0, 0.0)]
    assert math.isclose(creatures[0].hp, 82.0, abs_tol=1e-9)
    assert proj.life_timer == 0.25

    pool.update_demo(
        0.1,
        creatures,
        world_size=1024.0,
        speed_by_type={4: 100.0},
        damage_by_type={4: 18.0},
    )
    assert math.isclose(proj.life_timer, 0.15, abs_tol=1e-9)


def test_projectile_pool_demo_type_0x0b_does_not_splash_nearby_creatures() -> None:
    pool = ProjectilePool(size=1)
    pool.spawn(pos_x=0.0, pos_y=0.0, angle=math.pi / 2.0, type_id=0x0B, owner_id=-100)
    creatures = [
        _Creature(x=10.0, y=0.0, hp=100.0),
        _Creature(x=50.0, y=0.0, hp=100.0),
        _Creature(x=200.0, y=0.0, hp=100.0),
    ]
    pool.update_demo(
        0.1,
        creatures,
        world_size=1024.0,
        speed_by_type={0x0B: 100.0},
        damage_by_type={0x0B: 32.0},
    )
    assert math.isclose(creatures[0].hp, 68.0, abs_tol=1e-9)
    assert math.isclose(creatures[1].hp, 100.0, abs_tol=1e-9)
    assert math.isclose(creatures[2].hp, 100.0, abs_tol=1e-9)


def test_projectile_pool_demo_ion_minigun_linger_deals_aoe_damage() -> None:
    pool = ProjectilePool(size=1)
    pool.spawn(pos_x=0.0, pos_y=0.0, angle=math.pi / 2.0, type_id=0x16, owner_id=-100)
    creatures = [_Creature(x=10.0, y=0.0, hp=100.0)]

    pool.update_demo(
        0.1,
        creatures,
        world_size=1024.0,
        speed_by_type={0x16: 100.0},
        damage_by_type={0x16: 5.0},
    )
    assert math.isclose(creatures[0].hp, 95.0, abs_tol=1e-9)

    pool.update_demo(
        0.1,
        creatures,
        world_size=1024.0,
        speed_by_type={0x16: 100.0},
        damage_by_type={0x16: 5.0},
    )
    assert math.isclose(creatures[0].hp, 91.0, abs_tol=1e-9)


def test_secondary_projectile_pool_pulse_switches_to_detonation() -> None:
    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos_x=0.0, pos_y=0.0, angle=0.0, type_id=4)
    creatures = [_Creature(x=0.0, y=0.0, hp=100.0)]

    pool.update_pulse_gun(0.01, creatures)
    entry = pool.entries[0]
    assert entry.active
    assert entry.type_id == 3
    assert math.isclose(entry.vel_x, 0.0, abs_tol=1e-9)
    assert math.isclose(entry.vel_y, 0.25, abs_tol=1e-9)
    assert math.isclose(entry.trail_timer, 0.0, abs_tol=1e-9)

    hp_after_hit = creatures[0].hp
    pool.update_pulse_gun(0.1, creatures)
    assert creatures[0].hp < hp_after_hit

    pool.update_pulse_gun(0.25, creatures)
    assert not entry.active


def test_secondary_projectile_pool_timeout_switches_to_generic_detonation() -> None:
    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos_x=0.0, pos_y=0.0, angle=0.0, type_id=4, time_to_live=0.01)
    creatures: list[_Creature] = []

    pool.update_pulse_gun(0.02, creatures)
    entry = pool.entries[0]
    assert entry.active
    assert entry.type_id == 3
    assert math.isclose(entry.vel_x, 0.0, abs_tol=1e-9)
    assert math.isclose(entry.vel_y, 0.5, abs_tol=1e-9)


def test_secondary_projectile_pool_type1_accelerates_and_counts_down() -> None:
    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos_x=0.0, pos_y=0.0, angle=0.0, type_id=1, time_to_live=2.0)

    pool.update_pulse_gun(0.1, [])
    entry = pool.entries[0]

    assert entry.active
    assert entry.type_id == 1

    # Movement happens before acceleration in `projectile_update`.
    assert math.isclose(entry.pos_y, -9.0, abs_tol=1e-9)

    # Seeker Rockets (type 1): accelerate by factor (1.0 + dt * 3.0) while speed < 500.
    assert math.isclose(entry.vel_y, -117.0, abs_tol=1e-9)
    assert math.isclose(entry.speed, 1.9, abs_tol=1e-9)

    # No further acceleration once past the 500 speed threshold.
    entry.vel_x = 0.0
    entry.vel_y = -600.0
    pool.update_pulse_gun(0.1, [])
    assert math.isclose(entry.vel_y, -600.0, abs_tol=1e-9)


def test_secondary_projectile_pool_type1_hit_switches_to_detonation_scale() -> None:
    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos_x=0.0, pos_y=0.0, angle=0.0, type_id=1)

    creatures = [_Creature(x=0.0, y=0.0, hp=1000.0)]

    pool.update_pulse_gun(0.01, creatures)
    entry = pool.entries[0]
    assert entry.active
    assert entry.type_id == 3
    assert math.isclose(entry.vel_x, 0.0, abs_tol=1e-9)
    assert math.isclose(entry.vel_y, 1.0, abs_tol=1e-9)


def test_secondary_projectile_pool_type2_picks_nearest_target_and_steers() -> None:
    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos_x=0.0, pos_y=0.0, angle=0.0, type_id=2)
    creatures = [
        _Creature(x=100.0, y=0.0, hp=100.0),
        _Creature(x=200.0, y=0.0, hp=100.0),
    ]

    pool.update_pulse_gun(0.01, creatures)
    entry = pool.entries[0]
    assert entry.active
    assert entry.type_id == 2
    assert entry.target_id == 0
    assert entry.angle != 0.0
    assert abs(entry.vel_x) > 0.0


def test_secondary_projectile_pool_hit_queues_sfx_and_fx() -> None:
    state = GameplayState()
    fx_queue = FxQueue()

    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos_x=0.0, pos_y=0.0, angle=0.0, type_id=2)

    creatures = [_Creature(x=0.0, y=0.0, hp=1000.0)]

    pool.update_pulse_gun(0.01, creatures, runtime_state=state, fx_queue=fx_queue, detail_preset=5)
    entry = pool.entries[0]
    assert entry.active
    assert entry.type_id == 3
    assert math.isclose(entry.vel_x, 0.0, abs_tol=1e-9)
    assert math.isclose(entry.vel_y, 0.35, abs_tol=1e-9)

    assert state.sfx_queue == ["sfx_explosion_medium"]
    assert fx_queue.count == 13

    pool.update_pulse_gun(0.5, creatures, runtime_state=state, fx_queue=fx_queue, detail_preset=5)
    assert not entry.active
    assert any(int(fx_entry.effect_id) == 0x10 for fx_entry in fx_queue.iter_active())
