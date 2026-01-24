from __future__ import annotations

from dataclasses import dataclass
import math

from crimson.projectiles import ProjectilePool, SecondaryProjectilePool


@dataclass(slots=True)
class _Creature:
    x: float
    y: float
    hp: float


def test_projectile_pool_keeps_flight_timer_when_in_bounds() -> None:
    pool = ProjectilePool(size=1)
    idx = pool.spawn(pos_x=0.0, pos_y=0.0, angle=math.pi / 2.0, type_id=5, owner_id=-100)
    proj = pool.entries[idx]
    assert proj.active
    assert proj.life_timer == 0.4

    pool.update_demo(
        0.1,
        [],
        world_size=1024.0,
        speed_by_type={5: 100.0},
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
        type_id=5,
        owner_id=-100,
        base_damage=15.0,
    )
    proj = pool.entries[idx]

    pool.update(0.1, [], world_size=1024.0, damage_scale_by_type={5: 1.0})

    assert proj.active
    assert proj.life_timer == 0.4
    assert math.isclose(proj.pos_x, 30.0, abs_tol=1e-9)


def test_projectile_pool_update_applies_distance_scaled_damage() -> None:
    pool = ProjectilePool(size=1)
    pool.spawn(
        pos_x=0.0,
        pos_y=0.0,
        angle=math.pi / 2.0,
        type_id=5,
        owner_id=-100,
        base_damage=15.0,
    )

    creatures = [_Creature(x=41.1428575, y=0.0, hp=100.0)]
    hits = pool.update(0.1, creatures, world_size=1024.0, damage_scale_by_type={5: 1.0})

    assert hits == [(5, 0.0, 0.0, 30.0, 0.0)]
    assert math.isclose(creatures[0].hp, 33.5, abs_tol=1e-9)


def test_projectile_pool_update_ion_minigun_linger_deals_aoe_damage() -> None:
    pool = ProjectilePool(size=1)
    pool.spawn(
        pos_x=0.0,
        pos_y=0.0,
        angle=math.pi / 2.0,
        type_id=0x15,
        owner_id=-100,
        base_damage=20.0,
    )
    creatures = [_Creature(x=40.0, y=0.0, hp=200.0)]

    pool.update(0.1, creatures, world_size=1024.0, damage_scale_by_type={0x15: 1.4})
    hp_after_hit = creatures[0].hp

    pool.update(0.1, creatures, world_size=1024.0, damage_scale_by_type={0x15: 1.4})
    assert creatures[0].hp < hp_after_hit


def test_projectile_pool_emits_hit_event_and_enters_hit_state() -> None:
    pool = ProjectilePool(size=1)
    idx = pool.spawn(pos_x=0.0, pos_y=0.0, angle=math.pi / 2.0, type_id=5, owner_id=-100)
    proj = pool.entries[idx]

    creatures = [_Creature(x=10.0, y=0.0, hp=100.0)]
    hits = pool.update_demo(
        0.1,
        creatures,
        world_size=1024.0,
        speed_by_type={5: 100.0},
        damage_by_type={5: 18.0},
    )

    assert hits == [(5, 0.0, 0.0, 10.0, 0.0)]
    assert math.isclose(creatures[0].hp, 82.0, abs_tol=1e-9)
    assert proj.life_timer == 0.25

    pool.update_demo(
        0.1,
        creatures,
        world_size=1024.0,
        speed_by_type={5: 100.0},
        damage_by_type={5: 18.0},
    )
    assert math.isclose(proj.life_timer, 0.15, abs_tol=1e-9)


def test_projectile_pool_rocket_splash_hits_nearby_creatures() -> None:
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
        rocket_splash_radius=90.0,
    )
    assert math.isclose(creatures[0].hp, 68.0, abs_tol=1e-9)
    assert math.isclose(creatures[1].hp, 68.0, abs_tol=1e-9)
    assert math.isclose(creatures[2].hp, 100.0, abs_tol=1e-9)


def test_projectile_pool_ion_minigun_linger_deals_aoe_damage() -> None:
    pool = ProjectilePool(size=1)
    pool.spawn(pos_x=0.0, pos_y=0.0, angle=math.pi / 2.0, type_id=0x15, owner_id=-100)
    creatures = [_Creature(x=10.0, y=0.0, hp=100.0)]

    pool.update_demo(
        0.1,
        creatures,
        world_size=1024.0,
        speed_by_type={0x15: 100.0},
        damage_by_type={0x15: 5.0},
    )
    assert math.isclose(creatures[0].hp, 95.0, abs_tol=1e-9)

    pool.update_demo(
        0.1,
        creatures,
        world_size=1024.0,
        speed_by_type={0x15: 100.0},
        damage_by_type={0x15: 5.0},
    )
    assert math.isclose(creatures[0].hp, 85.0, abs_tol=1e-9)


def test_secondary_projectile_pool_pulse_switches_to_detonation() -> None:
    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos_x=0.0, pos_y=0.0, angle=0.0, type_id=4)
    creatures = [_Creature(x=0.0, y=0.0, hp=100.0)]

    pool.update_pulse_gun(0.01, creatures)
    entry = pool.entries[0]
    assert entry.active
    assert entry.type_id == 3
    assert entry.speed == 0.25
    assert entry.lifetime == 0.0

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
    assert entry.speed == 0.5


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
