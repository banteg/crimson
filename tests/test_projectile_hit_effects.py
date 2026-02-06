from __future__ import annotations

from grim.geom import Vec2

import pytest

from crimson.creatures.runtime import CreatureState
from crimson.gameplay import GameplayState
from crimson.projectiles import ProjectilePool, ProjectileTypeId


def test_plasma_cannon_hit_spawns_rings_and_sfx() -> None:
    pool = ProjectilePool(size=64)
    creature = CreatureState(active=True, hp=100.0, pos=Vec2(), size=50.0)
    runtime_state = GameplayState()

    pool.spawn(
        pos=Vec2(),
        angle=0.0,
        type_id=ProjectileTypeId.PLASMA_CANNON,
        owner_id=-100,
        base_damage=10.0,
    )

    pool.update(
        0.016,
        [creature],
        world_size=4096.0,
        detail_preset=5,
        rng=lambda: 0,
        runtime_state=runtime_state,
    )

    assert runtime_state.sfx_queue == ["sfx_explosion_medium", "sfx_shockwave"]

    rings = [entry for entry in runtime_state.effects.iter_active() if int(entry.effect_id) == 1]
    assert len(rings) == 2
    assert sorted(float(entry.scale_step) for entry in rings) == pytest.approx([45.0, 67.5])

    spawned = [p for p in pool.entries if p.active and int(p.type_id) == int(ProjectileTypeId.PLASMA_RIFLE)]
    assert len(spawned) == 12


def test_splitter_gun_hit_spawns_split_projectiles_and_sparks() -> None:
    pool = ProjectilePool(size=64)
    creature = CreatureState(active=True, hp=100.0, pos=Vec2(), size=50.0)
    runtime_state = GameplayState()

    pool.spawn(
        pos=Vec2(),
        angle=0.0,
        type_id=ProjectileTypeId.SPLITTER_GUN,
        owner_id=-100,
        base_damage=30.0,
    )

    pool.update(
        0.016,
        [creature],
        world_size=4096.0,
        detail_preset=5,
        rng=lambda: 0,
        runtime_state=runtime_state,
    )

    sparks = [entry for entry in runtime_state.effects.iter_active() if int(entry.effect_id) == 0]
    assert len(sparks) == 3
    assert all(int(entry.flags) == 0x19 for entry in sparks)

    split = [p for p in pool.entries if p.active and int(p.type_id) == int(ProjectileTypeId.SPLITTER_GUN) and int(p.owner_id) == 0]
    assert len(split) == 2
