from __future__ import annotations

import math

import msgspec
import pytest

from crimson.render.rtx.continuous_beam import (
    SUPPORT,
    beam_shape,
    beam_uniform,
    prepare_beam_lights,
)
from crimson.render.rtx.material_lights import MAX_SELECTED_SOURCES, MaterialLight
from grim.geom import Vec2


def light() -> MaterialLight:
    return MaterialLight(
        Vec2(128, 40),
        10000,
        (1, 1, 1),
        height=24,
        direction=Vec2(1, 0),
        length=256,
        beam_profile=(56.0, 9.0, 1.05),
        beam_ion=True,
    )


def test_shared_streak_profiles_match_authored_weapon_sizes() -> None:
    from crimson.projectiles.types import Projectile
    from crimson.projectiles.types import ProjectileTemplateId as PT
    from crimson.render.beam_profiles import STREAK_SCALES
    from crimson.render.rtx.material_lights import projectile_source

    for kind, scale in ((PT.ION_MINIGUN, 1.05), (PT.ION_RIFLE, 2.2), (PT.ION_CANNON, 3.5), (PT.FIRE_BULLETS, 0.8)):
        source = projectile_source(Projectile(active=True, type_id=kind, life_timer=0.4))
        assert source is not None
        assert STREAK_SCALES[kind] == scale
        assert source.beam_profile == (16 * scale, min(scale * 3.1, 9), 1.35 if kind == PT.FIRE_BULLETS else 1.05)


def test_beam_shape_gives_the_head_less_of_a_longer_beam() -> None:
    for profile in ((16.8, 3.255, 1.05), (35.2, 6.82, 1.05), (56.0, 9.0, 1.05), (12.8, 2.48, 1.35)):
        radius, _, head = profile
        shares = []
        for length in (0.0, 0.001, 1.0, 16.0, 193.7, 256.0):
            head_share, head_half_width, support = beam_shape(length, *profile)
            assert all(math.isfinite(value) for value in (head_share, head_half_width, support))
            assert 0 < head_share <= 1
            assert 0 < head_half_width < radius * head * SUPPORT
            assert support == pytest.approx(length * .5 + radius * head * SUPPORT)
            shares.append(head_share)
        # A shot just fired is all head; its growing trail takes ever more of the energy.
        assert shares[0] == 1 and shares == sorted(shares, reverse=True) and shares[-1] < .5
    assert beam_shape.cache_info().maxsize == 128
    assert not any(beam_uniform(msgspec.structs.replace(light(), illumination_gain=0)))
    assert not any(beam_uniform(msgspec.structs.replace(light(), beam_profile=None)))
    assert beam_uniform(light())[2] == 1.0
    assert beam_uniform(msgspec.structs.replace(light(), beam_ion=False))[2] == 0.0


def test_lit_slot_keeps_its_mask_profile_when_sources_swap() -> None:
    from crimson.projectiles.types import Projectile
    from crimson.projectiles.types import ProjectileTemplateId as PT
    from crimson.render.rtx.material_lights import projectile_source, select_material_lights

    # Lamps that fill the illumination budget but one; the union takes turns, so the last of them gives way.
    lamps = MAX_SELECTED_SOURCES - 1
    projectiles = [
        Projectile(active=True, type_id=PT.ION_CANNON, life_timer=0.4, origin=Vec2(-28, 300), pos=Vec2(228, 300))
        for _ in range(lamps)
    ]
    projectiles += [
        Projectile(active=True, type_id=PT.ION_MINIGUN, life_timer=life, origin=Vec2(-28, 100), pos=Vec2(228, 100))
        for life in (0.4, 0.36)
    ]

    def selected():
        sources = [source for ident, projectile in enumerate(projectiles)
                   if (source := projectile_source(projectile, ident)) is not None]
        sources[:lamps] = [msgspec.structs.replace(source, reflection_gain=0.) for source in sources[:lamps]]
        return select_material_lights(sources, view_center=Vec2(100, 100))

    first = selected()
    assert len(first) == MAX_SELECTED_SOURCES and first[-2].illumination_gain > 0 and first[-1].illumination_gain == 0
    assert (first[-2].ident, first[-1].ident) == (lamps, lamps + 1)
    before, _ = prepare_beam_lights(first)
    projectiles[-2].life_timer, projectiles[-1].life_timer = 0.36, 0.4
    second = selected()
    # The brighter source takes the lit slot; the mask profile follows the slot, not the source.
    assert len(second) == MAX_SELECTED_SOURCES and second[-2].illumination_gain > 0 and second[-1].illumination_gain == 0
    assert (second[-2].ident, second[-1].ident) == (lamps + 1, lamps)
    after, _ = prepare_beam_lights(second)
    row_size, lit = 4, MAX_SELECTED_SOURCES - 2
    for rows in (before, after):
        assert any(rows[lit * row_size : (lit + 1) * row_size]) and not any(rows[(lit + 1) * row_size :])
    assert prepare_beam_lights([]) == ([], [])
    nonbeam = MaterialLight(Vec2(), 100, (1, 1, 1), length=250)
    values, grid = prepare_beam_lights([nonbeam])
    assert not any(values) and grid == [nonbeam]


def test_beam_support_extends_source_culling_without_secondary_lists() -> None:
    from crimson.render.rtx.reflection_occlusion import CROWD_BODIES, BodyVolume, build_occlusion_grid

    original = light()
    shapes, grid_sources = prepare_beam_lights([original])
    margin = max(shapes[3::4])
    assert margin == pytest.approx(original.length / 2 + 56 * 1.05 * SUPPORT)
    assert grid_sources[0].source_width == original.source_width
    assert grid_sources[0].length == original.length + 2 * 56 * 1.05 * SUPPORT
    assert original.source_width == 3 and original.length == 256
    # As many as one cell lists before it is a crowd.
    bodies = [BodyVolume(Vec2(110, 90), Vec2(12, 9), 50, 0, opacity=0.5) for _ in range(CROWD_BODIES)]
    grid = build_occlusion_grid(bodies, grid_sources, width=256, height=256)
    assert grid.body_count == len(bodies)
    # Only ordinary point-ray lists are packed, including for beams. No unused
    # transforms or secondary entries can remain behind those lists.
    headers = grid.columns * grid.rows
    assert all(grid.values[i * 4 + 2:i * 4 + 4] == [0, 0] for i in range(headers))
    assert len(grid.values) == headers * 4 + grid.body_count * 12 + grid.references * 4
    # A wide point source still widens the shared ordinary penumbra lists.
    blast = MaterialLight(Vec2(100, 90), 300, (1, 1, 1), source_width=28)
    widened = build_occlusion_grid(bodies, [*grid_sources, blast], width=256, height=256)
    assert widened.references > grid.references
    zero = msgspec.structs.replace(original, length=0, direction=Vec2())
    zero_shapes, zero_grid = prepare_beam_lights([zero])
    assert zero_grid[0].direction == Vec2(1, 0)
    assert zero_grid[0].length > 0 and all(math.isfinite(value) for value in zero_shapes)


@pytest.mark.parametrize("heading", [0.0, 0.7, 2.5, -1.3])
def test_new_beam_uses_stored_heading_before_its_trail_grows(heading) -> None:
    from crimson.projectiles.types import Projectile
    from crimson.projectiles.types import ProjectileTemplateId as PT
    from crimson.render.rtx.material_lights import projectile_source

    origin = Vec2(100, 100)
    direction = Vec2.from_heading(heading)
    projectile = Projectile(
        active=True, type_id=PT.ION_CANNON, life_timer=0.4, angle=heading, pos=origin, origin=origin,
    )
    zero = projectile_source(projectile)
    assert zero is not None
    for distance in (0.0, 0.0000001, 0.001, 1.0):
        projectile.pos = origin + direction * distance
        source = projectile_source(projectile)
        assert source is not None
        assert source.direction.x == pytest.approx(direction.x, abs=1e-7)
        assert source.direction.y == pytest.approx(direction.y, abs=1e-7)
        shapes, grid_sources = prepare_beam_lights([source])
        assert all(math.isfinite(value) for value in shapes)
        assert grid_sources[0].direction == source.direction
