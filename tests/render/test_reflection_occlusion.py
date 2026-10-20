from __future__ import annotations

import math

import pytest

from crimson.creatures.runtime import CreatureState
from crimson.creatures.spawn import CreatureTypeId
from crimson.render.rtx.material_lights import MaterialLight
from crimson.render.rtx.reflection_occlusion import (
    CELL_SIZE,
    BodyVolume,
    build_occlusion_grid,
    creature_body_volumes,
)
from grim.geom import Vec2


def test_body_profiles_rotate_and_scale_with_the_drawn_sprite() -> None:
    for species in CreatureTypeId:
        creature = CreatureState(active=True, hp=100, type_id=species, pos=Vec2(100, 200), size=50)
        bodies = creature_body_volumes(creature)
        if not bodies:
            continue
        assert len(bodies) == 2
        creature.heading += math.pi / 2
        rotated = creature_body_volumes(creature)
        creature.size *= 2
        doubled = creature_body_volumes(creature)
        for a, b, c in zip(bodies, rotated, doubled, strict=True):
            delta = a.pos - creature.pos
            assert (b.pos - creature.pos).x == pytest.approx(-delta.y)
            assert (b.pos - creature.pos).y == pytest.approx(delta.x)
            assert c.radii == b.radii * 2
            assert c.height == b.height * 2
            assert c.pos - creature.pos == (b.pos - creature.pos) * 2
        creature.hp = 0
        assert not creature_body_volumes(creature)
        creature.hp = 100
        creature.active = False
        assert not creature_body_volumes(creature)


def test_spatial_grid_keeps_dense_overlaps_without_priority_truncation() -> None:
    bodies = [BodyVolume(Vec2(100, 100), Vec2(8, 14), 24, i * .01) for i in range(384)]
    light = MaterialLight(Vec2(100, 90), 100, (1, 1, 1), illumination_gain=0)
    grid = build_occlusion_grid(bodies, [light], width=1024, height=1024)
    x = math.floor((100 - grid.origin.x) / CELL_SIZE)
    y = math.floor((100 - grid.origin.y) / CELL_SIZE)
    assert grid.body_count == 384
    offset, count = grid.values[(y * grid.columns + x) * 4:][:2]
    assert count == 384
    addresses = {grid.values[(int(offset) + i) * 4] for i in range(int(count))}
    assert len(addresses) == 384
    assert build_occlusion_grid(bodies, [], width=1024, height=1024).body_count == 0


def test_source_culling_retains_long_tracer_and_rejects_distant_bodies() -> None:
    near = BodyVolume(Vec2(50, 50), Vec2(8, 14), 24, 0)
    far = BodyVolume(Vec2(50, 900), Vec2(8, 14), 24, 0)
    source = MaterialLight(Vec2(900, 50), 1, (1, 1, 1), direction=Vec2(1, 0), length=1800,
                           illumination_gain=0, reflection_radius=100)
    assert build_occlusion_grid([near, far], [source], width=1024, height=1024).body_count == 1



def test_dense_grid_uses_smaller_cells_without_dropping_volumes() -> None:
    body = BodyVolume(Vec2(100, 100), Vec2(8, 14), 24, 0)
    source = MaterialLight(Vec2(100, 90), 100, (1, 1, 1))
    small = build_occlusion_grid([body], [source], width=1024, height=1024)
    dense = build_occlusion_grid([body] * 512, [source], width=1024, height=1024)
    assert small.cell_size == 64
    assert dense.cell_size == 32
    assert dense.body_count == 512


def test_illumination_only_grid_support_and_explicit_energetic_profiles():
    from crimson.projectiles.types import ProjectileTemplateId as PT
    from crimson.render.rtx.material_lights import PROJECTILE_EMISSIONS

    expected = {PT.ION_RIFLE, PT.ION_MINIGUN, PT.ION_CANNON, PT.FIRE_BULLETS,
                PT.PLASMA_MINIGUN, PT.PLASMA_RIFLE, PT.PLASMA_CANNON}
    assert {kind for kind, profile in PROJECTILE_EMISSIONS.items() if profile.broad_illumination} == expected
    body = BodyVolume(Vec2(100, 100), Vec2(8, 14), 24, 0)
    source = MaterialLight(Vec2(100, 90), 100, (1, 1, 1), reflection_gain=0, reflection_radius=1)
    grid = build_occlusion_grid([body], [source], width=1024, height=1024)
    assert grid.body_count == 1


def test_shadows_off_uses_only_reflection_support_without_dropping_reflectors():
    body = BodyVolume(Vec2(100, 100), Vec2(8, 14), 24, 0)
    illumination_only = MaterialLight(Vec2(100, 90), 100, (1, 1, 1), reflection_gain=0)
    assert build_occlusion_grid([body], [illumination_only], width=1024, height=1024, illumination=False).body_count == 0
    reflected = MaterialLight(Vec2(900, 900), 1500, (1, 1, 1), reflection_radius=10)
    assert build_occlusion_grid([body], [reflected], width=1024, height=1024).body_count == 1
    assert build_occlusion_grid([body], [reflected], width=1024, height=1024, illumination=False).body_count == 0
    near = MaterialLight(Vec2(100, 90), 100, (1, 1, 1), illumination_gain=0)
    assert build_occlusion_grid([body], [near], width=1024, height=1024, illumination=False).body_count == 1
