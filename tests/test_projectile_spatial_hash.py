from __future__ import annotations

from dataclasses import dataclass

from crimson.creatures.spawn import CreatureFlags
from crimson.projectiles import SecondaryProjectilePool
from crimson.projectiles.runtime.spatial_hash import CreatureSpatialHash
from crimson.projectiles.types import Damageable
from grim.geom import Vec2


@dataclass(slots=True)
class _Creature:
    pos: Vec2
    hp: float
    active: bool = True
    hitbox_size: float = 16.0
    size: float = 50.0
    flags: CreatureFlags = CreatureFlags(0)
    plague_infected: bool = False


def _is_collidable(creature: Damageable) -> bool:
    return bool(creature.active) and float(creature.hitbox_size) > 5.0


def test_creature_spatial_hash_returns_sorted_candidates_across_cells() -> None:
    # Keep the lower index in a later cell so bucket traversal order differs from index order.
    creatures: list[_Creature] = [
        _Creature(pos=Vec2(130.0, 0.0), hp=1.0),
        _Creature(pos=Vec2(70.0, 0.0), hp=1.0),
    ]
    spatial = CreatureSpatialHash(creatures=creatures, is_collidable=_is_collidable)

    candidates = spatial.candidate_indices(pos=Vec2(96.0, 0.0), radius=8.0)

    assert candidates == [0, 1]


def test_creature_spatial_hash_sync_updates_membership() -> None:
    creatures: list[_Creature] = [_Creature(pos=Vec2(16.0, 16.0), hp=1.0)]
    spatial = CreatureSpatialHash(creatures=creatures, is_collidable=_is_collidable)

    assert 0 in spatial.candidate_indices(pos=Vec2(16.0, 16.0), radius=8.0)

    creatures[0].active = False
    spatial.sync_index(0)
    assert 0 not in spatial.candidate_indices(pos=Vec2(16.0, 16.0), radius=8.0)

    creatures[0].active = True
    creatures[0].pos = Vec2(196.0, 16.0)
    spatial.sync_index(0)
    assert 0 not in spatial.candidate_indices(pos=Vec2(16.0, 16.0), radius=8.0)
    assert 0 in spatial.candidate_indices(pos=Vec2(196.0, 16.0), radius=8.0)


def test_secondary_projectile_hit_order_matches_linear_index_scan() -> None:
    pool = SecondaryProjectilePool(size=1)
    pool.spawn(pos=Vec2(96.0, 0.0), angle=0.0, type_id=1, time_to_live=2.0)
    creatures: list[_Creature] = [
        _Creature(pos=Vec2(130.0, -9.0), hp=1000.0, size=500.0),
        _Creature(pos=Vec2(70.0, -9.0), hp=1000.0, size=500.0),
    ]

    hit_indices: list[int] = []

    def _apply(idx: int, damage: float, damage_type: int, impulse: Vec2, owner_id: int) -> None:
        _ = (damage, damage_type, impulse, owner_id)
        hit_indices.append(int(idx))

    pool.update_pulse_gun(0.1, creatures, apply_creature_damage=_apply)

    assert hit_indices == [0]
