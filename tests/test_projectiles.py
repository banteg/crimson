from __future__ import annotations

from grim.color import RGBA
from grim.geom import Vec2

from dataclasses import dataclass
import math

from crimson.gameplay import GameplayState
from crimson.sim.state_types import PlayerState
from crimson.effects import FxQueue
from crimson.projectiles import ProjectileHit, ProjectilePool, SecondaryProjectilePool
from crimson.projectiles import ProjectileTypeId


@dataclass(slots=True)
class _Creature:
    pos: Vec2
    hp: float
    active: bool = True
    hitbox_size: float = 16.0
    size: float = 50.0
    flags: int = 0
    plague_infected: bool = False


def _fixed_rng(value: int):
    def _rng() -> int:
        return value

    return _rng


def _expected_damage(dist: float, damage_scale: float = 1.0) -> float:
    if dist < 50.0:
        dist = 50.0
    return ((100.0 / dist) * damage_scale * 30.0 + 10.0) * 0.95


def _hit(*, type_id: int, origin_x: float, origin_y: float, hit_x: float, hit_y: float, target_x: float, target_y: float) -> ProjectileHit:
    return ProjectileHit(
        type_id=int(type_id),
        origin=Vec2(origin_x, origin_y),
        hit=Vec2(hit_x, hit_y),
        target=Vec2(target_x, target_y),
    )


def test_projectile_pool_keeps_flight_timer_when_in_bounds() -> None:
    pool = ProjectilePool(size=1)
    idx = pool.spawn(pos=Vec2(), angle=math.pi / 2.0, type_id=4, owner_id=-100)
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
    assert math.isclose(proj.pos.x, 10.0, abs_tol=1e-9)


def test_projectile_pool_update_moves_by_projectile_meta() -> None:
    pool = ProjectilePool(size=1)
    idx = pool.spawn(
        pos=Vec2(),
        angle=math.pi / 2.0,
        type_id=4,
        owner_id=-100,
        base_damage=15.0,
    )
    proj = pool.entries[idx]

    pool.update(0.1, [], world_size=1024.0, damage_scale_by_type={4: 1.0})

    assert proj.active
    assert proj.life_timer == 0.4
    assert math.isclose(proj.pos.x, 90.0, abs_tol=1e-9)


def test_projectile_pool_update_applies_distance_scaled_damage() -> None:
    pool = ProjectilePool(size=1)
    pool.spawn(
        pos=Vec2(),
        angle=math.pi / 2.0,
        type_id=4,
        owner_id=-100,
        base_damage=15.0,
    )

    creatures = [_Creature(pos=Vec2(41.1428575, 0.0), hp=100.0)]
    hits = pool.update(0.1, creatures, world_size=1024.0, damage_scale_by_type={4: 1.0})

    assert hits == [_hit(type_id=4, origin_x=0.0, origin_y=0.0, hit_x=30.0, hit_y=0.0, target_x=41.1428575, target_y=0.0)]
    assert math.isclose(creatures[0].hp, 33.5, abs_tol=1e-9)


def test_projectile_pool_update_applies_rng_jitter_to_hit_position() -> None:
    pool = ProjectilePool(size=1)
    idx = pool.spawn(
        pos=Vec2(),
        angle=math.pi / 2.0,
        type_id=4,
        owner_id=-100,
        base_damage=30.0,
    )
    creatures = [_Creature(pos=Vec2(71.1428574, 0.0), hp=100.0)]

    hits = pool.update(
        0.1,
        creatures,
        world_size=1024.0,
        damage_scale_by_type={4: 1.0},
        rng=_fixed_rng(2),
    )

    assert hits == [_hit(type_id=4, origin_x=0.0, origin_y=0.0, hit_x=60.0, hit_y=0.0, target_x=71.1428574, target_y=0.0)]
    proj = pool.entries[idx]
    assert math.isclose(proj.pos.x, 62.0, abs_tol=1e-9)
    assert proj.life_timer == 0.25

    expected_damage = _expected_damage(62.0, 1.0)
    assert math.isclose(creatures[0].hp, 100.0 - expected_damage, abs_tol=1e-6)


def test_projectile_pool_update_type_0x0b_does_not_splash_damage() -> None:
    pool = ProjectilePool(size=1)
    pool.spawn(
        pos=Vec2(),
        angle=math.pi / 2.0,
        type_id=0x0B,
        owner_id=-100,
        base_damage=30.0,
    )
    creatures = [
        _Creature(pos=Vec2(71.1428574, 0.0), hp=100.0),
        _Creature(pos=Vec2(100.0, 0.0), hp=100.0),
        _Creature(pos=Vec2(160.0, 0.0), hp=100.0),
        _Creature(pos=Vec2(220.0, 0.0), hp=100.0),
    ]

    hits = pool.update(
        0.1,
        creatures,
        world_size=1024.0,
        damage_scale_by_type={0x0B: 1.0},
        rng=_fixed_rng(0),
    )

    assert hits == [_hit(type_id=0x0B, origin_x=0.0, origin_y=0.0, hit_x=60.0, hit_y=0.0, target_x=71.1428574, target_y=0.0)]
    assert math.isclose(creatures[0].hp, 100.0 - _expected_damage(60.0), abs_tol=1e-6)
    assert math.isclose(creatures[1].hp, 100.0, abs_tol=1e-9)
    assert math.isclose(creatures[2].hp, 100.0, abs_tol=1e-9)
    assert math.isclose(creatures[3].hp, 100.0, abs_tol=1e-9)


def test_projectile_pool_update_type_0x0b_does_not_splash_nearby_creatures() -> None:
    pool = ProjectilePool(size=1)
    pool.spawn(
        pos=Vec2(),
        angle=math.pi / 2.0,
        type_id=0x0B,
        owner_id=-100,
        base_damage=15.0,
    )
    creatures = [
        _Creature(pos=Vec2(30.0, 0.0), hp=100.0),
        _Creature(pos=Vec2(70.0, 0.0), hp=100.0),
        _Creature(pos=Vec2(200.0, 0.0), hp=100.0),
    ]

    pool.update(0.1, creatures, world_size=1024.0, damage_scale_by_type={0x0B: 1.0})

    assert creatures[0].hp < 100.0
    assert math.isclose(creatures[1].hp, 100.0, abs_tol=1e-9)
    assert math.isclose(creatures[2].hp, 100.0, abs_tol=1e-9)


def test_projectile_pool_update_ion_minigun_linger_deals_aoe_damage() -> None:
    pool = ProjectilePool(size=1)
    pool.spawn(
        pos=Vec2(),
        angle=math.pi / 2.0,
        type_id=0x16,
        owner_id=-100,
        base_damage=20.0,
    )
    creatures = [_Creature(pos=Vec2(40.0, 0.0), hp=200.0)]

    pool.update(0.1, creatures, world_size=1024.0, damage_scale_by_type={0x16: 1.4})
    hp_after_hit = creatures[0].hp

    pool.update(0.1, creatures, world_size=1024.0, damage_scale_by_type={0x16: 1.4})
    assert creatures[0].hp < hp_after_hit


def test_projectile_pool_update_expired_ion_still_runs_linger_once() -> None:
    pool = ProjectilePool(size=1)
    idx = pool.spawn(
        pos=Vec2(),
        angle=math.pi / 2.0,
        type_id=int(ProjectileTypeId.ION_RIFLE),
        owner_id=-100,
        base_damage=20.0,
    )
    proj = pool.entries[idx]
    proj.life_timer = -0.001
    creatures = [_Creature(pos=Vec2(5.0, 0.0), hp=-1.0, hitbox_size=6.0)]

    calls: list[tuple[int, float, int, Vec2, int]] = []

    def _apply_damage(creature_index: int, damage: float, damage_type: int, impulse: Vec2, owner_id: int) -> None:
        calls.append((int(creature_index), float(damage), int(damage_type), impulse, int(owner_id)))

    pool.update(
        0.021,
        creatures,
        world_size=1024.0,
        apply_creature_damage=_apply_damage,
    )

    assert proj.active is False
    assert math.isclose(float(proj.life_timer), -0.022, abs_tol=1e-9)
    assert len(calls) == 1
    creature_index, damage, damage_type, impulse, owner_id = calls[0]
    assert creature_index == 0
    assert math.isclose(damage, 2.1, abs_tol=1e-9)
    assert damage_type == 7
    assert impulse == Vec2()
    assert owner_id == -100


def test_projectile_life_timer_f32_decay_delays_deactivate_by_one_tick() -> None:
    pool = ProjectilePool(size=1)
    idx = pool.spawn(
        pos=Vec2(1200.0, 1200.0),
        angle=math.pi / 2.0,
        type_id=int(ProjectileTypeId.SPLITTER_GUN),
        owner_id=0,
        base_damage=1.0,
    )
    proj = pool.entries[idx]

    for _ in range(4):
        pool.update(0.1, [], world_size=1024.0)

    assert proj.active is True
    assert 0.0 < float(proj.life_timer) < 5e-8

    pool.update(0.1, [], world_size=1024.0)
    assert proj.active is True
    assert proj.life_timer < 0.0
    assert math.isclose(float(proj.life_timer), -0.09999998658895493, abs_tol=1e-9)

    pool.update(0.1, [], world_size=1024.0)
    assert proj.active is False


def test_projectile_pool_update_ion_hit_spawns_ring_and_burst_effects() -> None:
    state = GameplayState()
    state.projectiles.spawn(
        pos=Vec2(),
        angle=math.pi / 2.0,
        type_id=int(ProjectileTypeId.ION_MINIGUN),
        owner_id=-100,
        base_damage=20.0,
    )
    creatures = [_Creature(pos=Vec2(10.0, 0.0), hp=100.0)]

    state.projectiles.update(
        0.1,
        creatures,
        world_size=1024.0,
        damage_scale_by_type={int(ProjectileTypeId.ION_MINIGUN): 1.0},
        detail_preset=5,
        rng=_fixed_rng(0),
        runtime_state=state,
        players=[PlayerState(index=0, pos=Vec2())],
    )

    active = state.effects.iter_active()
    rings = [entry for entry in active if int(entry.effect_id) == 1]
    bursts = [entry for entry in active if int(entry.effect_id) == 0]
    assert len(rings) == 1
    assert len(bursts) == 3

    ring = rings[0]
    [proj] = [entry for entry in state.projectiles.entries if entry.active]
    assert math.isclose(float(ring.pos.x), float(proj.pos.x), abs_tol=1e-9)
    assert math.isclose(float(ring.pos.y), float(proj.pos.y), abs_tol=1e-9)
    assert math.isclose(float(ring.half_width), 4.0, abs_tol=1e-9)
    assert math.isclose(float(ring.half_height), 4.0, abs_tol=1e-9)
    assert math.isclose(float(ring.scale_step), 67.5, abs_tol=1e-9)
    assert math.isclose(float(ring.lifetime), 0.08, abs_tol=1e-9)

    burst = bursts[0]
    assert math.isclose(float(burst.half_width), 20.48, abs_tol=1e-6)
    assert math.isclose(float(burst.half_height), 20.48, abs_tol=1e-6)
    assert math.isclose(float(burst.lifetime), 0.448, abs_tol=1e-6)


def test_projectile_pool_update_owner_collision_blocks_later_candidates() -> None:
    pool = ProjectilePool(size=4)
    creatures = [
        _Creature(pos=Vec2(10.0, 0.0), hp=100.0),
        _Creature(pos=Vec2(10.0, 0.0), hp=100.0),
    ]

    pool.spawn(
        pos=Vec2(),
        angle=math.pi / 2.0,
        type_id=4,
        owner_id=0,
        base_damage=15.0,
    )

    hits = pool.update(0.1, creatures, world_size=1024.0, rng=_fixed_rng(0), runtime_state=GameplayState())

    # Native `creature_find_in_radius` returns the first match even when it's the
    # owner, and `projectile_update` does not continue searching for a later
    # creature in that branch.
    assert hits == []
    assert math.isclose(creatures[0].hp, 100.0, abs_tol=1e-9)
    assert math.isclose(creatures[1].hp, 100.0, abs_tol=1e-9)


def test_projectile_pool_emits_hit_event_and_enters_hit_state() -> None:
    pool = ProjectilePool(size=1)
    idx = pool.spawn(pos=Vec2(), angle=math.pi / 2.0, type_id=4, owner_id=-100)
    proj = pool.entries[idx]

    creatures = [_Creature(pos=Vec2(10.0, 0.0), hp=100.0)]
    hits = pool.update_demo(
        0.1,
        creatures,
        world_size=1024.0,
        speed_by_type={4: 100.0},
        damage_by_type={4: 18.0},
    )

    assert hits == [_hit(type_id=4, origin_x=0.0, origin_y=0.0, hit_x=10.0, hit_y=0.0, target_x=10.0, target_y=0.0)]
    assert math.isclose(creatures[0].hp, 82.0, abs_tol=1e-9)
    assert proj.life_timer == 0.25

    pool.update_demo(
        0.1,
        creatures,
        world_size=1024.0,
        speed_by_type={4: 100.0},
        damage_by_type={4: 18.0},
    )
    assert math.isclose(proj.life_timer, 0.15, abs_tol=1e-6)


def test_projectile_pool_demo_type_0x0b_does_not_splash_nearby_creatures() -> None:
    pool = ProjectilePool(size=1)
    pool.spawn(pos=Vec2(), angle=math.pi / 2.0, type_id=0x0B, owner_id=-100)
    creatures = [
        _Creature(pos=Vec2(10.0, 0.0), hp=100.0),
        _Creature(pos=Vec2(50.0, 0.0), hp=100.0),
        _Creature(pos=Vec2(200.0, 0.0), hp=100.0),
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
    pool.spawn(pos=Vec2(), angle=math.pi / 2.0, type_id=0x16, owner_id=-100)
    creatures = [_Creature(pos=Vec2(10.0, 0.0), hp=100.0)]

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
    pool.spawn(pos=Vec2(), angle=0.0, type_id=4)
    creatures = [_Creature(pos=Vec2(), hp=100.0)]

    pool.update_pulse_gun(0.01, creatures)
    entry = pool.entries[0]
    assert entry.active
    assert entry.type_id == 3
    assert entry.vel == Vec2()
    assert math.isclose(entry.detonation_t, 0.0, abs_tol=1e-9)
    assert math.isclose(entry.detonation_scale, 0.25, abs_tol=1e-9)
    assert math.isclose(entry.trail_timer, 0.0, abs_tol=1e-9)

    hp_after_hit = creatures[0].hp
    pool.update_pulse_gun(0.1, creatures)
    assert creatures[0].hp < hp_after_hit

    pool.update_pulse_gun(0.25, creatures)
    assert not entry.active


def test_secondary_projectile_pool_timeout_switches_to_generic_detonation() -> None:
    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos=Vec2(), angle=0.0, type_id=4, time_to_live=0.01)
    creatures: list[_Creature] = []

    pool.update_pulse_gun(0.02, creatures)
    entry = pool.entries[0]
    assert entry.active
    assert entry.type_id == 3
    assert entry.vel == Vec2()
    assert math.isclose(entry.detonation_t, 0.0, abs_tol=1e-9)
    assert math.isclose(entry.detonation_scale, 0.5, abs_tol=1e-9)


def test_secondary_projectile_pool_type1_accelerates_and_counts_down() -> None:
    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos=Vec2(), angle=0.0, type_id=1, time_to_live=2.0)

    pool.update_pulse_gun(0.1, [])
    entry = pool.entries[0]

    assert entry.active
    assert entry.type_id == 1

    # Movement happens before acceleration in `projectile_update`.
    assert math.isclose(entry.pos.y, -9.0, abs_tol=1e-9)

    # Seeker Rockets (type 1): accelerate by factor (1.0 + dt * 3.0) while speed < 500.
    assert math.isclose(entry.vel.y, -117.0, abs_tol=1e-9)
    assert math.isclose(entry.speed, 1.9, abs_tol=1e-9)

    # No further acceleration once past the 500 speed threshold.
    entry.vel = Vec2(0.0, -600.0)
    pool.update_pulse_gun(0.1, [])
    assert math.isclose(entry.vel.y, -600.0, abs_tol=1e-9)


def test_secondary_projectile_pool_type1_hit_switches_to_detonation_scale() -> None:
    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos=Vec2(), angle=0.0, type_id=1)

    creatures = [_Creature(pos=Vec2(), hp=1000.0)]

    pool.update_pulse_gun(0.01, creatures)
    entry = pool.entries[0]
    assert entry.active
    assert entry.type_id == 3
    assert entry.vel == Vec2()
    assert math.isclose(entry.detonation_t, 0.0, abs_tol=1e-9)
    assert math.isclose(entry.detonation_scale, 1.0, abs_tol=1e-9)


def test_secondary_projectile_pool_type2_picks_nearest_target_and_steers() -> None:
    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos=Vec2(), angle=0.0, type_id=2)
    creatures = [
        _Creature(pos=Vec2(100.0, 0.0), hp=100.0),
        _Creature(pos=Vec2(200.0, 0.0), hp=100.0),
    ]

    pool.update_pulse_gun(0.01, creatures)
    entry = pool.entries[0]
    assert entry.active
    assert entry.type_id == 2
    assert entry.target_id == 0
    assert entry.angle != 0.0
    assert abs(entry.vel.x) > 0.0


def test_secondary_projectile_pool_type2_uses_hint_for_initial_target() -> None:
    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos=Vec2(), angle=0.0, type_id=2, target_hint=Vec2(1000.0, 0.0))
    creatures = [
        _Creature(pos=Vec2(100.0, 0.0), hp=100.0),
        _Creature(pos=Vec2(1000.0, 0.0), hp=100.0),
    ]

    pool.update_pulse_gun(0.01, creatures)
    entry = pool.entries[0]
    assert entry.active
    assert entry.type_id == 2
    assert entry.target_id == 1
    assert entry.target_hint_active is False


def test_secondary_projectile_pool_type2_seeds_target_id_at_spawn_when_creatures_available() -> None:
    pool = SecondaryProjectilePool(size=1)
    creatures = [
        _Creature(pos=Vec2(100.0, 0.0), hp=100.0),
        _Creature(pos=Vec2(1000.0, 0.0), hp=100.0),
    ]

    idx = pool.spawn(
        pos=Vec2(),
        angle=0.0,
        type_id=2,
        target_hint=Vec2(1000.0, 0.0),
        creatures=creatures,
    )

    entry = pool.entries[idx]
    assert entry.active
    assert entry.type_id == 2
    assert entry.target_id == 1
    assert entry.target_hint_active is False


def test_secondary_projectile_pool_type2_target_pick_uses_active_hitbox_sentinel() -> None:
    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos=Vec2(), angle=0.0, type_id=2, target_hint=Vec2(300.0, 0.0))
    creatures = [
        _Creature(pos=Vec2(300.0, 0.0), hp=100.0, hitbox_size=15.0),
        _Creature(pos=Vec2(500.0, 0.0), hp=0.0, hitbox_size=16.0),
    ]

    pool.update_pulse_gun(0.01, creatures)
    entry = pool.entries[0]
    assert entry.active
    assert entry.type_id == 2
    assert entry.target_id == 1


def test_secondary_projectile_pool_hit_queues_sfx_and_fx() -> None:
    state = GameplayState()
    fx_queue = FxQueue()

    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos=Vec2(), angle=0.0, type_id=2)

    creatures = [_Creature(pos=Vec2(), hp=1000.0)]

    pool.update_pulse_gun(0.01, creatures, runtime_state=state, fx_queue=fx_queue, detail_preset=5)
    entry = pool.entries[0]
    assert entry.active
    assert entry.type_id == 3
    assert entry.vel == Vec2()
    assert math.isclose(entry.detonation_t, 0.0, abs_tol=1e-9)
    assert math.isclose(entry.detonation_scale, 0.35, abs_tol=1e-9)

    assert state.sfx_queue == ["sfx_explosion_medium"]
    assert fx_queue.count == 13

    pool.update_pulse_gun(0.5, creatures, runtime_state=state, fx_queue=fx_queue, detail_preset=5)
    assert not entry.active
    assert any(int(fx_entry.effect_id) == 0x10 for fx_entry in fx_queue.iter_active())


def test_secondary_projectile_pool_hit_scan_ignores_hp_gate_and_uses_active_flag() -> None:
    state = GameplayState()
    fx_queue = FxQueue()

    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos=Vec2(), angle=0.0, type_id=2)

    creatures = [_Creature(pos=Vec2(), hp=0.0, active=True, hitbox_size=16.0)]

    pool.update_pulse_gun(0.01, creatures, runtime_state=state, fx_queue=fx_queue, detail_preset=5)
    entry = pool.entries[0]
    assert entry.active
    assert entry.type_id == 3


def test_secondary_projectile_pool_detonation_radius_does_not_pad_creature_radius() -> None:
    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos=Vec2(), angle=0.0, type_id=3, time_to_live=1.0)

    # dt=0.25 => t=0.75 => radius = 1.0 * 0.75 * 80 = 60.
    # Keep the creature just outside the raw radius; old code padded by creature radius.
    creatures = [_Creature(pos=Vec2(70.0, 0.0), hp=100.0)]
    pool.update_pulse_gun(0.25, creatures)
    assert math.isclose(creatures[0].hp, 100.0, abs_tol=1e-9)


def test_secondary_projectile_pool_detonation_sets_camera_shake_pulses() -> None:
    state = GameplayState()

    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos=Vec2(), angle=0.0, type_id=3, time_to_live=1.0)
    pool.update_pulse_gun(0.01, [], runtime_state=state)

    assert state.camera_shake_pulses == 4


def test_secondary_projectile_pool_direct_hit_passes_impulse() -> None:
    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos=Vec2(), angle=0.0, type_id=1, time_to_live=2.0)
    creatures = [_Creature(pos=Vec2(0.0, -9.0), hp=1000.0)]

    calls: list[tuple[float, float]] = []

    def _apply(idx: int, damage: float, damage_type: int, impulse: Vec2, owner_id: int) -> None:
        calls.append((float(impulse.x), float(impulse.y)))

    pool.update_pulse_gun(0.1, creatures, apply_creature_damage=_apply)

    assert len(calls) == 1
    impulse_x, impulse_y = calls[0]
    assert abs(impulse_x) < 1e-6
    assert math.isclose(impulse_y, -1170.0, abs_tol=1e-6)


def test_secondary_projectile_pool_detonation_aoe_passes_impulse() -> None:
    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos=Vec2(), angle=0.0, type_id=3, time_to_live=1.0)
    creatures = [_Creature(pos=Vec2(3.0, 4.0), hp=1000.0)]

    calls: list[tuple[float, float]] = []

    def _apply(idx: int, damage: float, damage_type: int, impulse: Vec2, owner_id: int) -> None:
        calls.append((float(impulse.x), float(impulse.y)))

    pool.update_pulse_gun(0.1, creatures, apply_creature_damage=_apply)

    assert len(calls) == 1
    impulse_x, impulse_y = calls[0]
    assert math.isclose(impulse_x, 0.06, abs_tol=1e-9)
    assert math.isclose(impulse_y, 0.08, abs_tol=1e-9)


def test_secondary_projectile_pool_detonation_kill_triggers_native_followup() -> None:
    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos=Vec2(), angle=0.0, type_id=3, time_to_live=1.0)
    creatures = [_Creature(pos=Vec2(0.0, 0.0), hp=20.0)]
    fx_queue = FxQueue()

    damage_calls: list[int] = []

    def _apply(idx: int, damage: float, damage_type: int, impulse: Vec2, owner_id: int) -> None:
        _ = (damage_type, impulse, owner_id)
        damage_calls.append(int(idx))
        creatures[int(idx)].hp -= float(damage)

    followup_kills: list[int] = []

    pool.update_pulse_gun(
        0.1,
        creatures,
        apply_creature_damage=_apply,
        fx_queue=fx_queue,
        on_detonation_kill=lambda idx: followup_kills.append(int(idx)),
    )

    assert damage_calls == [0]
    assert creatures[0].hp < 0.0
    assert followup_kills == [0]
    assert fx_queue.count == 2


def test_secondary_projectile_pool_detonation_nonlethal_skips_followup() -> None:
    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos=Vec2(), angle=0.0, type_id=3, time_to_live=1.0)
    creatures = [_Creature(pos=Vec2(0.0, 0.0), hp=200.0)]
    fx_queue = FxQueue()

    def _apply(idx: int, damage: float, damage_type: int, impulse: Vec2, owner_id: int) -> None:
        _ = (damage_type, impulse, owner_id)
        creatures[int(idx)].hp -= float(damage)

    followup_kills: list[int] = []

    pool.update_pulse_gun(
        0.1,
        creatures,
        apply_creature_damage=_apply,
        fx_queue=fx_queue,
        on_detonation_kill=lambda idx: followup_kills.append(int(idx)),
    )

    assert creatures[0].hp > 0.0
    assert followup_kills == []
    assert fx_queue.count == 0


def test_secondary_projectile_pool_freeze_spawns_extra_shards_and_burst() -> None:
    class _FixedRng:
        def rand(self) -> int:
            return 0

    class _Bonuses:
        freeze: float = 1.0

    class _Effects:
        def __init__(self) -> None:
            self.calls: list[tuple[float, float]] = []

        def spawn_freeze_shard(self, *, pos: Vec2, angle: float, rand, detail_preset: int) -> None:  # noqa: ANN001
            self.calls.append((float(pos.x), float(pos.y)))

    @dataclass(slots=True)
    class _SpriteEntry:
        color: RGBA = RGBA()

    class _Sprites:
        def __init__(self) -> None:
            self.entries: list[_SpriteEntry] = []

        def spawn(self, *, pos: Vec2, vel: Vec2, scale: float, color: RGBA | None = None) -> int:
            self.entries.append(_SpriteEntry(color=RGBA() if color is None else color))
            return len(self.entries) - 1

    class _RuntimeState:
        def __init__(self) -> None:
            self.rng = _FixedRng()
            self.bonuses = _Bonuses()
            self.effects = _Effects()
            self.sprite_effects = _Sprites()
            self.sfx_queue: list[str] = []

    runtime = _RuntimeState()

    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos=Vec2(), angle=0.0, type_id=4)
    pool.entries[0].trail_timer = 1.0

    creatures = [_Creature(pos=Vec2(0.0, -4.0), hp=1000.0)]
    pool.update_pulse_gun(0.1, creatures, runtime_state=runtime, detail_preset=5)

    # Freeze bonus spawns 4 shards at impact, then 8 more on conversion.
    assert len(runtime.effects.calls) == 12
    assert all(math.isclose(y, -9.0, abs_tol=1e-9) for _, y in runtime.effects.calls[:4])
    assert all(math.isclose(y, -4.0, abs_tol=1e-9) for _, y in runtime.effects.calls[4:])

    # The 10-sprite burst happens regardless of freeze.
    assert len(runtime.sprite_effects.entries) == 10
