from __future__ import annotations

from crimson.creatures.runtime import CreatureState
from crimson.projectiles.runtime import SecondaryProjectilePool, SecondarySpawnSpec, SecondaryStepCtx
from crimson.projectiles.runtime.spatial_hash import CreatureSpatialHash
from crimson.projectiles.types import SecondaryProjectileTypeId
from grim.geom import Vec2
from tests.support.factories import RecordingCreatureDamageRuntime
from tests.support.factories import make_creature_state as _creature


def _is_collidable(creature: CreatureState) -> bool:
    return bool(creature.active) and float(creature.lifecycle_stage) > 5.0


def test_creature_spatial_hash_returns_sorted_candidates_across_cells() -> None:
    # Keep the lower index in a later cell so bucket traversal order differs from index order.
    creatures: list[CreatureState] = [
        _creature(pos=Vec2(130.0, 0.0), hp=1.0),
        _creature(pos=Vec2(70.0, 0.0), hp=1.0),
    ]
    spatial = CreatureSpatialHash(creatures=creatures, is_collidable=_is_collidable)

    candidates = spatial.candidate_indices(pos=Vec2(96.0, 0.0), radius=8.0)

    assert candidates == [0, 1]


def test_creature_spatial_hash_sync_updates_membership() -> None:
    creatures: list[CreatureState] = [_creature(pos=Vec2(16.0, 16.0), hp=1.0)]
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
    pool.spawn_from_spec(
        SecondarySpawnSpec(
            pos=Vec2(96.0, 0.0),
            angle=0.0,
            type_id=SecondaryProjectileTypeId.ROCKET,
            time_to_live=2.0,
        ),
    )
    creatures: list[CreatureState] = [
        _creature(pos=Vec2(130.0, -9.0), hp=1000.0, size=500.0),
        _creature(pos=Vec2(70.0, -9.0), hp=1000.0, size=500.0),
    ]

    damage_runtime = RecordingCreatureDamageRuntime(creatures=creatures, apply_damage=False)

    pool.step(SecondaryStepCtx(dt=0.1, creatures=creatures, creature_damage_runtime=damage_runtime))

    assert [call[0] for call in damage_runtime.calls] == [0]
