from __future__ import annotations

import math
from typing import Any

from syrupy import SnapshotAssertion

from crimson.creatures.runtime import CreatureState
from crimson.effects import FxQueue
from crimson.gameplay import GameplayState
from crimson.projectiles import ProjectileHit, ProjectilePool, ProjectileTypeId, SecondaryProjectilePool
from crimson.projectiles.runtime.collision import _within_native_find_radius
from grim.geom import Vec2
from tests.factories import make_creature_state as _creature
from tests.helpers import assert_float_close


def _fixed_rng(value: int):
    def _rng() -> int:
        return value

    return _rng


def _normalize_vec2(vec: Vec2) -> list[float]:
    return [round(float(vec.x), 6), round(float(vec.y), 6)]


def _normalize_hit(hit: ProjectileHit) -> dict[str, object]:
    return {
        "type_id": int(hit.type_id),
        "origin": _normalize_vec2(hit.origin),
        "hit": _normalize_vec2(hit.hit),
        "target": _normalize_vec2(hit.target),
    }


def _normalize_primary_pool(pool: ProjectilePool, idx: int, creatures: list[CreatureState], hits: list[ProjectileHit]) -> dict[str, object]:
    projectile = pool.entries[idx]
    return {
        "hits": [_normalize_hit(hit) for hit in hits],
        "projectile": {
            "active": bool(projectile.active),
            "type_id": int(projectile.type_id),
            "owner_id": int(projectile.owner_id),
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
            "target_hint_active": bool(entry.target_hint_active),
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
    threshold = radius + target_size * 0.14285715 + 3.0

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


def test_primary_projectile_update_snapshot(snapshot: SnapshotAssertion) -> None:
    cases: list[dict[str, Any]] = [
        {
            "name": "pistol_near_hit",
            "type_id": int(ProjectileTypeId.PISTOL),
            "base_damage": 15.0,
            "creatures": [
                _creature(pos=Vec2(41.1428575, 0.0), hp=100.0),
            ],
            "rng": None,
        },
        {
            "name": "pistol_rng_jitter",
            "type_id": int(ProjectileTypeId.PISTOL),
            "base_damage": 30.0,
            "creatures": [
                _creature(pos=Vec2(71.1428574, 0.0), hp=100.0),
            ],
            "rng": _fixed_rng(2),
        },
        {
            "name": "rocket_no_splash_type_0x0b",
            "type_id": 0x0B,
            "base_damage": 30.0,
            "creatures": [
                _creature(pos=Vec2(71.1428574, 0.0), hp=100.0),
                _creature(pos=Vec2(100.0, 0.0), hp=100.0),
                _creature(pos=Vec2(160.0, 0.0), hp=100.0),
            ],
            "rng": _fixed_rng(0),
        },
        {
            "name": "ion_minigun_linger",
            "type_id": 0x16,
            "base_damage": 20.0,
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
            type_id=int(case["type_id"]),
            owner_id=-100,
            base_damage=float(case["base_damage"]),
        )
        creatures = case["creatures"]
        damage_scale_by_type = case.get("damage_scale_by_type") or {int(case["type_id"]): 1.0}
        hits = pool.update(
            0.1,
            creatures,
            world_size=1024.0,
            damage_scale_by_type=damage_scale_by_type,
            rng=case.get("rng"),
        )
        if case.get("double_update", False):
            more_hits = pool.update(
                0.1,
                creatures,
                world_size=1024.0,
                damage_scale_by_type=damage_scale_by_type,
                rng=case.get("rng"),
            )
            hits = [*hits, *more_hits]

        snapshot(name=str(case["name"])).assert_match(_normalize_primary_pool(pool, idx, creatures, hits))


def test_projectile_pool_demo_update_snapshot(snapshot: SnapshotAssertion) -> None:
    pool = ProjectilePool(size=1)
    idx = pool.spawn(pos=Vec2(), angle=math.pi / 2.0, type_id=4, owner_id=-100)
    pool.update_demo(
        0.1,
        [],
        world_size=1024.0,
        speed_by_type={4: 100.0},
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


def test_secondary_projectile_pool_snapshot(snapshot: SnapshotAssertion) -> None:
    # Type 2: targeting pass
    pool = SecondaryProjectilePool(size=1)
    idx = pool.spawn(pos=Vec2(), angle=0.0, type_id=2, target_hint=Vec2(1000.0, 0.0))
    creatures: list[CreatureState] = [
        _creature(pos=Vec2(100.0, 0.0), hp=100.0),
        _creature(pos=Vec2(1000.0, 0.0), hp=100.0),
    ]
    pool.update_pulse_gun(0.01, creatures)
    snapshot(name="seek_target").assert_match(_normalize_secondary_pool(pool, idx, creatures))

    # Type 3: detonation pass + runtime side effects
    runtime_state = GameplayState()
    fx_queue = FxQueue()
    detonation_pool = SecondaryProjectilePool(size=1)
    detonation_idx = detonation_pool.spawn(pos=Vec2(), angle=0.0, type_id=3, time_to_live=1.0)
    detonation_creatures: list[CreatureState] = [_creature(pos=Vec2(3.0, 4.0), hp=1000.0)]
    detonation_pool.update_pulse_gun(
        0.1,
        detonation_creatures,
        runtime_state=runtime_state,
        fx_queue=fx_queue,
        detail_preset=5,
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


def test_secondary_projectile_impulse_callbacks_snapshot(snapshot: SnapshotAssertion, mocker) -> None:
    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos=Vec2(), angle=0.0, type_id=1, time_to_live=2.0)
    creatures: list[CreatureState] = [_creature(pos=Vec2(0.0, -9.0), hp=1000.0)]

    apply_damage = mocker.Mock()
    pool.update_pulse_gun(0.1, creatures, apply_creature_damage=apply_damage)

    snapshot.assert_match(
        [
            {
                "idx": int(call.args[0]),
                "damage": round(float(call.args[1]), 6),
                "damage_type": int(call.args[2]),
                "impulse": _normalize_vec2(call.args[3]),
                "owner_id": int(call.args[4]),
            }
            for call in apply_damage.call_args_list
        ],
    )


def test_secondary_projectile_kill_followup_snapshot(snapshot: SnapshotAssertion, mocker) -> None:
    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos=Vec2(), angle=0.0, type_id=3, time_to_live=1.0)
    creatures: list[CreatureState] = [_creature(pos=Vec2(0.0, 0.0), hp=20.0)]
    fx_queue = FxQueue()

    def _apply(idx: int, damage: float, damage_type: int, impulse: Vec2, owner_id: int) -> None:
        _ = (damage_type, impulse, owner_id)
        creatures[int(idx)].hp -= float(damage)

    on_kill = mocker.Mock()
    pool.update_pulse_gun(
        0.1,
        creatures,
        apply_creature_damage=_apply,
        fx_queue=fx_queue,
        on_detonation_kill=on_kill,
    )

    snapshot.assert_match(
        {
            "creature_hp": round(float(creatures[0].hp), 6),
            "followup_calls": [int(call.args[0]) for call in on_kill.call_args_list],
            "fx_count": int(fx_queue.count),
        },
    )

    assert_float_close(abs(float(pool.entries[0].vel.x)), 0.0)
