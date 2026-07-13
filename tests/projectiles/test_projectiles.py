from __future__ import annotations

import math
from typing import Any

from syrupy import SnapshotAssertion

import crimson.projectiles.runtime.projectile_pool as projectile_pool_runtime
from crimson.collision_math import native_find_size_margin
from crimson.creatures.runtime import CreatureState
from crimson.effects import FxQueue
from crimson.gameplay import GameplayState
from crimson.math_parity import NATIVE_HALF_PI, f32
from crimson.owner_ref import OwnerRef
from crimson.projectiles.runtime import (
    PrimaryStepCtx,
    ProjectilePool,
    SecondaryProjectilePool,
    SecondarySpawnSpec,
    SecondaryStepCtx,
    projectile_collision_profile,
)
from crimson.projectiles.runtime.collision import _within_native_find_radius
from crimson.projectiles.types import (
    ProjectileCollisionProfile,
    ProjectileHit,
    ProjectileTemplateId,
    SecondaryProjectileTypeId,
)
from crimson.rng_caller_static import RngCallerStatic
from grim.geom import Vec2
from tests.support.factories import RecordingCreatureDamageRuntime, make_projectile_update_options
from tests.support.factories import make_creature_state as _creature
from tests.support.helpers import ScriptedCrand, assert_float_close


def _fixed_rng(value: int) -> ScriptedCrand:
    return ScriptedCrand(value, fallback=ScriptedCrand.Fallback.REPEAT_LAST)


def test_projectile_damage_formula_uses_native_per_operation_f32_stores() -> None:
    damage = projectile_pool_runtime._projectile_damage_amount_f32(
        331.64129638671875,
        4.1,
    )

    assert damage == 44.73385238647461


def test_stop_on_hit_jitter_rounds_multiply_before_position_add() -> None:
    result = projectile_pool_runtime._stop_on_hit_jitter_axis_f32(
        0.8021621757752091,
        2,
        356.32464599609375,
    )

    assert result == 357.928955078125


def test_projectile_heading_subtraction_uses_native_f32_store() -> None:
    angle = -2.5405335426330566
    dt = 0.04500000178813934
    radians = f32(angle - NATIVE_HALF_PI)

    step_x = f32(math.cos(radians) * dt * 20.0) * 3.0
    step_y = f32(math.sin(radians) * dt * 20.0) * 3.0

    assert f32(step_x) == -1.5268936157226562
    assert f32(step_y) == 2.2267906665802


def test_primary_projectile_integration_rounds_each_x87_operation() -> None:
    pool = ProjectilePool(size=1)
    idx = pool.spawn(
        pos=Vec2(-49.92948532104492, 681.1566772460938),
        angle=-0.8641037344932556,
        type_id=ProjectileTemplateId.PISTOL,
        owner=OwnerRef.from_local_player(0),
        travel_budget=55.0,
    )

    pool.step(
        PrimaryStepCtx(
            dt=0.06000000238418579,
            creatures=(),
            options=make_projectile_update_options(world_size=1024.0),
        ),
    )

    assert pool.entries[idx].pos == Vec2(-101.94862365722656, 636.7431030273438)


def test_gauss_linger_decay_rounds_multiply_before_subtraction() -> None:
    pool = ProjectilePool(size=1)
    idx = pool.spawn(
        pos=Vec2(),
        angle=0.0,
        type_id=ProjectileTemplateId.GAUSS_GUN,
        owner=OwnerRef.from_local_player(0),
    )
    pool.entries[idx].life_timer = 0.011000030674040318

    pool.step(
        PrimaryStepCtx(
            dt=0.08000000566244125,
            creatures=(),
            options=make_projectile_update_options(world_size=1024.0),
        ),
    )

    assert pool.entries[idx].life_timer == 0.003000030294060707


def _normalize_vec2(vec: Vec2) -> list[float]:
    return [round(float(vec.x), 6), round(float(vec.y), 6)]


def _normalize_hit(hit: ProjectileHit) -> dict[str, object]:
    return {
        "type_id": int(hit.type_id),
        "origin": _normalize_vec2(hit.origin),
        "hit": _normalize_vec2(hit.hit),
        "target": _normalize_vec2(hit.target),
    }


def _normalize_owner(owner: OwnerRef) -> dict[str, object]:
    return {
        "kind": int(owner.kind),
        "index": int(owner.index),
        "local_host": bool(owner.local_host),
    }


def _normalize_primary_pool(
    pool: ProjectilePool,
    idx: int,
    creatures: list[CreatureState],
    hits: list[ProjectileHit],
) -> dict[str, object]:
    projectile = pool.entries[idx]
    return {
        "hits": [_normalize_hit(hit) for hit in hits],
        "projectile": {
            "active": bool(projectile.active),
            "type_id": int(projectile.type_id),
            "owner": _normalize_owner(projectile.owner),
            "life_timer": round(float(projectile.life_timer), 6),
            "pos": _normalize_vec2(projectile.pos),
            "damage_pool": round(float(projectile.damage_pool), 6),
        },
        "creature_hp": [round(float(creature.hp), 6) for creature in creatures],
    }


def _normalize_secondary_pool(
    pool: SecondaryProjectilePool,
    idx: int,
    creatures: list[CreatureState],
    *,
    runtime_state: GameplayState | None = None,
    fx_queue: FxQueue | None = None,
) -> dict[str, object]:
    entry = pool.entries[idx]
    payload: dict[str, object] = {
        "entry": {
            "active": bool(entry.active),
            "type_id": int(entry.type_id),
            "target_id": int(entry.target_id),
            "pos": _normalize_vec2(entry.pos),
            "vel": _normalize_vec2(entry.vel),
            "angle": round(float(entry.angle), 6),
            "trail_timer": round(float(entry.trail_timer), 6),
            "detonation_t": round(float(entry.detonation_t), 6),
            "detonation_scale": round(float(entry.detonation_scale), 6),
        },
        "creature_hp": [round(float(creature.hp), 6) for creature in creatures],
    }
    if runtime_state is not None:
        payload["sfx_queue"] = list(runtime_state.sfx_queue)
        payload["camera_shake_pulses"] = int(runtime_state.camera_shake_pulses)
    if fx_queue is not None:
        payload["fx_count"] = int(fx_queue.count)
    return payload


def test_within_native_find_radius_uses_strict_boundary() -> None:
    origin = Vec2()
    radius = 30.0
    target_size = 50.0
    threshold = radius + native_find_size_margin(target_size)

    assert (
        _within_native_find_radius(
            origin=origin,
            target=Vec2(threshold - 0.0001, 0.0),
            radius=radius,
            target_size=target_size,
        )
        is True
    )
    assert (
        _within_native_find_radius(
            origin=origin,
            target=Vec2(threshold + 0.0006, 0.0),
            radius=radius,
            target_size=target_size,
        )
        is False
    )


def test_projectile_collision_profile_matches_native_spawn_constants() -> None:
    expected: dict[ProjectileTemplateId, ProjectileCollisionProfile] = {
        ProjectileTemplateId.ION_MINIGUN: ProjectileCollisionProfile(hit_radius=3.0, initial_damage_pool=1.0),
        ProjectileTemplateId.ION_RIFLE: ProjectileCollisionProfile(hit_radius=5.0, initial_damage_pool=1.0),
        ProjectileTemplateId.ION_CANNON: ProjectileCollisionProfile(hit_radius=10.0, initial_damage_pool=1.0),
        ProjectileTemplateId.PLASMA_CANNON: ProjectileCollisionProfile(hit_radius=10.0, initial_damage_pool=1.0),
        ProjectileTemplateId.GAUSS_GUN: ProjectileCollisionProfile(hit_radius=1.0, initial_damage_pool=300.0),
        ProjectileTemplateId.FIRE_BULLETS: ProjectileCollisionProfile(hit_radius=1.0, initial_damage_pool=240.0),
        ProjectileTemplateId.BLADE_GUN: ProjectileCollisionProfile(hit_radius=1.0, initial_damage_pool=50.0),
    }

    for type_id, profile in expected.items():
        assert projectile_collision_profile(type_id) == profile

    assert projectile_collision_profile(ProjectileTemplateId.PISTOL) == ProjectileCollisionProfile(
        hit_radius=1.0,
        initial_damage_pool=1.0,
    )


def test_primary_spawn_uses_collision_profile_defaults() -> None:
    pool = ProjectilePool(size=1)
    for type_id in (
        ProjectileTemplateId.PISTOL,
        ProjectileTemplateId.ION_MINIGUN,
        ProjectileTemplateId.ION_RIFLE,
        ProjectileTemplateId.ION_CANNON,
        ProjectileTemplateId.PLASMA_CANNON,
        ProjectileTemplateId.GAUSS_GUN,
        ProjectileTemplateId.FIRE_BULLETS,
        ProjectileTemplateId.BLADE_GUN,
    ):
        idx = pool.spawn(
            pos=Vec2(),
            angle=0.0,
            type_id=type_id,
            owner=OwnerRef.from_local_player(0),
        )
        entry = pool.entries[idx]
        profile = projectile_collision_profile(type_id)
        assert_float_close(float(entry.hit_radius), float(profile.hit_radius))
        assert_float_close(float(entry.damage_pool), float(profile.initial_damage_pool))
        pool.reset()


def test_primary_projectile_update_snapshot(snapshot: SnapshotAssertion) -> None:
    cases: list[dict[str, Any]] = [
        {
            "name": "pistol_near_hit",
            "type_id": ProjectileTemplateId.PISTOL,
            "travel_budget": 15.0,
            "creatures": [
                _creature(pos=Vec2(41.1428575, 0.0), hp=100.0),
            ],
            "rng": None,
        },
        {
            "name": "pistol_rng_jitter",
            "type_id": ProjectileTemplateId.PISTOL,
            "travel_budget": 30.0,
            "creatures": [
                _creature(pos=Vec2(71.1428574, 0.0), hp=100.0),
            ],
            "rng": _fixed_rng(2),
        },
        {
            "name": "rocket_no_splash_type_0x0b",
            "type_id": ProjectileTemplateId.PLASMA_MINIGUN,
            "travel_budget": 30.0,
            "creatures": [
                _creature(pos=Vec2(71.1428574, 0.0), hp=100.0),
                _creature(pos=Vec2(100.0, 0.0), hp=100.0),
                _creature(pos=Vec2(160.0, 0.0), hp=100.0),
            ],
            "rng": _fixed_rng(0),
        },
        {
            "name": "ion_minigun_linger",
            "type_id": ProjectileTemplateId.ION_MINIGUN,
            "travel_budget": 20.0,
            "creatures": [
                _creature(pos=Vec2(40.0, 0.0), hp=200.0),
            ],
            "rng": None,
            "double_update": True,
            "damage_scale_by_type": {0x16: 1.4},
        },
    ]

    for case in cases:
        pool = ProjectilePool(size=1)
        idx = pool.spawn(
            pos=Vec2(),
            angle=math.pi / 2.0,
            type_id=ProjectileTemplateId(int(case["type_id"])),
            owner=OwnerRef.from_local_player(0),
            travel_budget=float(case["travel_budget"]),
        )
        creatures = case["creatures"]
        damage_scale_by_type = case.get("damage_scale_by_type") or {int(case["type_id"]): 1.0}
        hits = pool.step(
            PrimaryStepCtx(
                dt=0.1,
                creatures=creatures,
                options=make_projectile_update_options(
                    world_size=1024.0,
                    damage_scale_by_type=damage_scale_by_type,
                    rng=case.get("rng"),
                ),
            ),
        )
        if case.get("double_update", False):
            more_hits = pool.step(
                PrimaryStepCtx(
                    dt=0.1,
                    creatures=creatures,
                    options=make_projectile_update_options(
                        world_size=1024.0,
                        damage_scale_by_type=damage_scale_by_type,
                        rng=case.get("rng"),
                    ),
                ),
            )
            hits = [*hits, *more_hits]

        snapshot(name=str(case["name"])).assert_match(_normalize_primary_pool(pool, idx, creatures, hits))


def test_projectile_pool_demo_update_snapshot(snapshot: SnapshotAssertion) -> None:
    pool = ProjectilePool(size=1)
    idx = pool.spawn(
        pos=Vec2(),
        angle=math.pi / 2.0,
        type_id=ProjectileTemplateId.ASSAULT_RIFLE,
        owner=OwnerRef.from_local_player(0),
    )
    pool.update_demo(
        0.1,
        [],
        world_size=1024.0,
        speed_by_type={int(ProjectileTemplateId.ASSAULT_RIFLE): 100.0},
        damage_by_type={},
    )

    entry = pool.entries[idx]
    snapshot.assert_match(
        {
            "active": bool(entry.active),
            "life_timer": round(float(entry.life_timer), 6),
            "pos": _normalize_vec2(entry.pos),
        },
    )


def test_primary_spawn_persists_velocity_vector() -> None:
    pool = ProjectilePool(size=1)
    idx = pool.spawn(
        pos=Vec2(12.0, 34.0),
        angle=math.pi / 3.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner=OwnerRef.from_local_player(0),
    )

    entry = pool.entries[idx]
    angle = float(f32(math.pi / 3.0))
    assert_float_close(float(entry.vel.x), float(f32(math.cos(float(angle)) * 1.5)))
    assert_float_close(float(entry.vel.y), float(f32(math.sin(float(angle)) * 1.5)))


def test_secondary_projectile_pool_snapshot(snapshot: SnapshotAssertion) -> None:
    # Type 2: targeting pass
    pool = SecondaryProjectilePool(size=1)
    creatures: list[CreatureState] = [
        _creature(pos=Vec2(100.0, 0.0), hp=100.0),
        _creature(pos=Vec2(1000.0, 0.0), hp=100.0),
    ]
    idx = pool.spawn_from_spec(
        SecondarySpawnSpec(
            pos=Vec2(),
            angle=0.0,
            type_id=SecondaryProjectileTypeId.HOMING_ROCKET,
            target_hint=Vec2(1000.0, 0.0),
            creatures=creatures,
        ),
    )
    pool.step(SecondaryStepCtx(dt=0.01, creatures=creatures))
    snapshot(name="seek_target").assert_match(_normalize_secondary_pool(pool, idx, creatures))

    # Type 3: detonation pass + runtime side effects
    runtime_state = GameplayState()
    fx_queue = FxQueue()
    detonation_pool = SecondaryProjectilePool(size=1)
    detonation_idx = detonation_pool.spawn_from_spec(
        SecondarySpawnSpec(
            pos=Vec2(),
            angle=0.0,
            type_id=SecondaryProjectileTypeId.DETONATION,
            time_to_live=1.0,
        ),
    )
    detonation_creatures: list[CreatureState] = [_creature(pos=Vec2(3.0, 4.0), hp=1000.0)]
    detonation_pool.step(
        SecondaryStepCtx(
            dt=0.1,
            creatures=detonation_creatures,
            runtime_state=runtime_state,
            fx_queue=fx_queue,
            detail_preset=5,
        ),
    )
    snapshot(name="detonation").assert_match(
        _normalize_secondary_pool(
            detonation_pool,
            detonation_idx,
            detonation_creatures,
            runtime_state=runtime_state,
            fx_queue=fx_queue,
        ),
    )


def test_homing_rocket_spawn_uses_native_trig_store_order() -> None:
    pool = SecondaryProjectilePool(size=1)

    idx = pool.spawn_from_spec(
        SecondarySpawnSpec(
            pos=Vec2(152.47727966308594, 941.5100708007812),
            angle=-4.161045551300049,
            type_id=SecondaryProjectileTypeId.HOMING_ROCKET,
        ),
    )

    projectile = pool.entries[idx]
    assert projectile.vel == Vec2(161.8461151123047, 99.52806091308594)


def test_homing_rocket_steering_rounds_each_x87_operation() -> None:
    pool = SecondaryProjectilePool(size=1)
    idx = pool.spawn_from_spec(
        SecondarySpawnSpec(
            pos=Vec2(193.97930908203125, 971.7576904296875),
            angle=0.0,
            type_id=SecondaryProjectileTypeId.HOMING_ROCKET,
        ),
    )
    projectile = pool.entries[idx]
    projectile.vel = Vec2(254.46153259277344, 234.05662536621094)
    projectile.target_id = 0
    projectile.trail_timer = 1.0
    creatures = [_creature(pos=Vec2(202.13153076171875, 991.8573608398438), hp=1000.0)]
    damage_runtime = RecordingCreatureDamageRuntime(creatures=creatures, apply_damage=False)

    hit_count = pool.step(
        SecondaryStepCtx(
            dt=0.05700000375509262,
            creatures=creatures,
            creature_damage_runtime=damage_runtime,
        ),
    )

    assert hit_count == 1
    impulse = damage_runtime.calls[0][3]
    assert impulse == Vec2(3916.34716796875, 4689.19384765625)


def test_homing_rocket_trail_decay_rounds_each_x87_operation() -> None:
    pool = SecondaryProjectilePool(size=1)
    idx = pool.spawn_from_spec(
        SecondarySpawnSpec(
            pos=Vec2(750.26220703125, 714.5313110351562),
            angle=-3.6826539039611816,
            type_id=SecondaryProjectileTypeId.HOMING_ROCKET,
        ),
    )
    projectile = pool.entries[idx]
    projectile.vel = Vec2(-65.83425903320312, -83.56523895263672)
    projectile.target_id = 0
    projectile.trail_timer = f32(0.06)
    creatures = [_creature(pos=Vec2(813.2255859375, 819.3178100585938), hp=1000.0)]

    pool.step(
        SecondaryStepCtx(
            dt=0.06200000271201134,
            creatures=creatures,
        ),
    )

    assert projectile.trail_timer == 0.009637407958507538


def test_secondary_projectile_impulse_callbacks_snapshot(snapshot: SnapshotAssertion) -> None:
    pool = SecondaryProjectilePool(size=1)
    pool.spawn_from_spec(
        SecondarySpawnSpec(pos=Vec2(), angle=0.0, type_id=SecondaryProjectileTypeId.ROCKET, time_to_live=2.0),
    )
    creatures: list[CreatureState] = [_creature(pos=Vec2(0.0, -9.0), hp=1000.0)]
    damage_runtime = RecordingCreatureDamageRuntime(creatures=creatures, apply_damage=False)

    pool.step(SecondaryStepCtx(dt=0.1, creatures=creatures, creature_damage_runtime=damage_runtime))

    snapshot.assert_match(
        [
            {
                "idx": int(call[0]),
                "damage": round(float(call[1]), 6),
                "damage_type": int(call[2]),
                "impulse": _normalize_vec2(call[3]),
                "owner": _normalize_owner(call[4]),
            }
            for call in damage_runtime.calls
        ],
    )


def test_secondary_projectile_kill_followup_snapshot(snapshot: SnapshotAssertion) -> None:
    pool = SecondaryProjectilePool(size=1)
    pool.spawn_from_spec(
        SecondarySpawnSpec(pos=Vec2(), angle=0.0, type_id=SecondaryProjectileTypeId.DETONATION, time_to_live=1.0),
    )
    creatures: list[CreatureState] = [_creature(pos=Vec2(0.0, 0.0), hp=20.0)]
    fx_queue = FxQueue()

    damage_runtime = RecordingCreatureDamageRuntime(creatures=creatures)
    pool.step(
        SecondaryStepCtx(
            dt=0.1,
            creatures=creatures,
            fx_queue=fx_queue,
            creature_damage_runtime=damage_runtime,
        ),
    )

    snapshot.assert_match(
        {
            "creature_hp": round(float(creatures[0].hp), 6),
            "followup_calls": list(damage_runtime.detonation_kills),
            "fx_count": int(fx_queue.count),
        },
    )

    assert pool.entries[0].vel == Vec2(f32(0.3), 1.0)


def test_secondary_detonation_damage_rounds_each_x87_operation() -> None:
    pool = SecondaryProjectilePool(size=1)
    pool.spawn_from_spec(
        SecondarySpawnSpec(
            pos=Vec2(),
            angle=0.0,
            type_id=SecondaryProjectileTypeId.DETONATION,
            time_to_live=0.5,
        ),
    )
    creatures = [_creature(pos=Vec2(), hp=1000.0)]
    damage_runtime = RecordingCreatureDamageRuntime(creatures=creatures, apply_damage=False)

    pool.step(
        SecondaryStepCtx(
            dt=0.06100000441074371,
            creatures=creatures,
            creature_damage_runtime=damage_runtime,
        ),
    )

    assert damage_runtime.calls[0][1] == 21.35000228881836


def _secondary_callers(rng: ScriptedCrand, allowed: set[RngCallerStatic]) -> list[RngCallerStatic]:
    return [RngCallerStatic(record.caller) for record in rng.records_since() if record.caller in allowed]


def test_secondary_rocket_hit_tags_exact_non_freeze_callers() -> None:
    pool = SecondaryProjectilePool(size=1)
    runtime_state = GameplayState()
    fx_queue = FxQueue()
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    runtime_state.rng = rng
    pool.spawn_from_spec(
        SecondarySpawnSpec(pos=Vec2(), angle=0.0, type_id=SecondaryProjectileTypeId.ROCKET, time_to_live=2.0),
    )
    creatures: list[CreatureState] = [_creature(pos=Vec2(0.0, -9.0), hp=1000.0)]

    hit_count = pool.step(
        SecondaryStepCtx(dt=0.1, creatures=creatures, runtime_state=runtime_state, fx_queue=fx_queue),
    )

    entry = pool.entries[0]
    assert hit_count == 1
    assert entry.type_id == SecondaryProjectileTypeId.DETONATION
    assert entry.vel == Vec2(0.0, 1.0)
    assert entry.trail_timer == f32(0.06)

    allowed = {
        RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_PRE_HIT_DECAL_DX_1,
        RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_PRE_HIT_DECAL_DY_1,
        RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_PRE_HIT_DECAL_DX_2,
        RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_PRE_HIT_DECAL_DY_2,
        RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_PRE_HIT_DECAL_DX_3,
        RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_PRE_HIT_DECAL_DY_3,
        RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_ROCKET_DECAL_ANGLE,
        RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_ROCKET_DECAL_RADIUS,
        RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_DETONATION_SPRITE_MAG,
    }
    assert (
        _secondary_callers(rng, allowed)
        == [
            RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_PRE_HIT_DECAL_DX_1,
            RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_PRE_HIT_DECAL_DY_1,
            RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_PRE_HIT_DECAL_DX_2,
            RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_PRE_HIT_DECAL_DY_2,
            RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_PRE_HIT_DECAL_DX_3,
            RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_PRE_HIT_DECAL_DY_3,
        ]
        + [
            caller
            for _ in range(20)
            for caller in (
                RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_ROCKET_DECAL_ANGLE,
                RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_ROCKET_DECAL_RADIUS,
            )
        ]
        + [RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_DETONATION_SPRITE_MAG] * 10
    )


def test_secondary_homing_rocket_hit_tags_exact_non_freeze_callers() -> None:
    pool = SecondaryProjectilePool(size=1)
    runtime_state = GameplayState()
    fx_queue = FxQueue()
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    runtime_state.rng = rng
    pool.spawn_from_spec(
        SecondarySpawnSpec(pos=Vec2(), angle=0.0, type_id=SecondaryProjectileTypeId.HOMING_ROCKET, time_to_live=2.0),
    )
    creatures: list[CreatureState] = [_creature(pos=Vec2(0.0, -9.0), hp=1000.0)]

    hit_count = pool.step(
        SecondaryStepCtx(dt=0.1, creatures=creatures, runtime_state=runtime_state, fx_queue=fx_queue),
    )

    entry = pool.entries[0]
    assert hit_count == 1
    assert entry.type_id == SecondaryProjectileTypeId.DETONATION
    assert entry.vel == Vec2(0.0, f32(0.35))
    assert entry.trail_timer == f32(0.06)

    allowed = {
        RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_SEEKER_ROCKET_DECAL_ANGLE,
        RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_SEEKER_ROCKET_DECAL_RADIUS,
        RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_DETONATION_SPRITE_MAG,
    }
    assert (
        _secondary_callers(rng, allowed)
        == [
            caller
            for _ in range(10)
            for caller in (
                RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_SEEKER_ROCKET_DECAL_ANGLE,
                RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_SEEKER_ROCKET_DECAL_RADIUS,
            )
        ]
        + [RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_DETONATION_SPRITE_MAG] * 10
    )


def test_secondary_rocket_minigun_hit_tags_exact_non_freeze_callers() -> None:
    pool = SecondaryProjectilePool(size=1)
    runtime_state = GameplayState()
    fx_queue = FxQueue()
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    runtime_state.rng = rng
    pool.spawn_from_spec(
        SecondarySpawnSpec(pos=Vec2(), angle=0.0, type_id=SecondaryProjectileTypeId.ROCKET_MINIGUN, time_to_live=2.0),
    )
    creatures: list[CreatureState] = [_creature(pos=Vec2(0.0, -9.0), hp=1000.0)]

    pool.step(SecondaryStepCtx(dt=0.1, creatures=creatures, runtime_state=runtime_state, fx_queue=fx_queue))

    allowed = {
        RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_ROCKET_MINIGUN_DECAL_ANGLE,
        RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_ROCKET_MINIGUN_DECAL_RADIUS,
        RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_DETONATION_SPRITE_MAG,
    }
    assert (
        _secondary_callers(rng, allowed)
        == [
            caller
            for _ in range(3)
            for caller in (
                RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_ROCKET_MINIGUN_DECAL_ANGLE,
                RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_ROCKET_MINIGUN_DECAL_RADIUS,
            )
        ]
        + [RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_DETONATION_SPRITE_MAG] * 10
    )


def test_secondary_homing_rocket_hit_tags_exact_freeze_callers() -> None:
    pool = SecondaryProjectilePool(size=1)
    runtime_state = GameplayState()
    runtime_state.bonuses.freeze = 1.0
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    runtime_state.rng = rng
    pool.spawn_from_spec(
        SecondarySpawnSpec(pos=Vec2(), angle=0.0, type_id=SecondaryProjectileTypeId.HOMING_ROCKET, time_to_live=2.0),
    )
    creatures: list[CreatureState] = [_creature(pos=Vec2(0.0, -9.0), hp=1000.0)]

    pool.step(SecondaryStepCtx(dt=0.1, creatures=creatures, runtime_state=runtime_state))

    allowed = {
        RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_PRE_HIT_FREEZE_SHARD_ANGLE,
        RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_SEEKER_ROCKET_FREEZE_SHARD_ANGLE,
        RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_DETONATION_SPRITE_MAG,
    }
    assert (
        _secondary_callers(rng, allowed)
        == [
            RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_PRE_HIT_FREEZE_SHARD_ANGLE,
        ]
        * 4
        + [
            RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_SEEKER_ROCKET_FREEZE_SHARD_ANGLE,
        ]
        * 8
        + [RngCallerStatic.SECONDARY_PROJECTILE_UPDATE_DETONATION_SPRITE_MAG] * 10
    )
