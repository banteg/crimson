from __future__ import annotations

import math

import msgspec
import pytest

from crimson.render.rtx.continuous_beam import (
    SOURCE_CELLS,
    SUPPORT,
    beam_cells,
    prepare_beam_lights,
)
from crimson.render.rtx.material_lights import MaterialLight
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


def test_source_cells_preserve_energy_head_and_finite_growing_profiles() -> None:
    from crimson.render.rtx.continuous_beam import SOURCE_CELLS, SUPPORT, source_cells

    for profile in ((16.8, 3.255, 1.05), (35.2, 6.82, 1.05), (56.0, 9.0, 1.05), (12.8, 2.48, 1.35)):
        for length in (0.0, 0.001, 1.0, 16.0, 193.7, 256.0):
            values = source_cells(length, *profile)
            assert len(values) == SOURCE_CELLS * 4
            assert sum(values[::4]) == pytest.approx(1.0)
            assert all(math.isfinite(v) for v in values)
            pad = profile[0] * profile[2] * SUPPORT
            span = length + 2 * pad
            for i in range(SOURCE_CELLS):
                mass, position, half_span, _ = values[i * 4 : i * 4 + 4]
                assert mass >= 0
                assert -pad - length * 0.5 + i * span / SOURCE_CELLS <= position
                assert position <= -pad - length * 0.5 + (i + 1) * span / SOURCE_CELLS
                assert 0 <= half_span <= span / SOURCE_CELLS
            if length == 0:
                assert values[0] == pytest.approx(values[8])
                assert values[1] == pytest.approx(-values[9])
            if length == 256:
                assert values[0] < values[4] < values[8]
    assert source_cells.cache_info().maxsize == 128
    assert not any(beam_cells(msgspec.structs.replace(light(), illumination_gain=0)))
    assert not any(beam_cells(msgspec.structs.replace(light(), beam_profile=None)))
    assert beam_cells(light())[3::4] == (1.0, 1.0, 1.0)


def test_lit_slot_keeps_its_mask_profile_when_sources_swap() -> None:
    from crimson.projectiles.types import Projectile
    from crimson.projectiles.types import ProjectileTemplateId as PT
    from crimson.render.rtx.material_lights import projectile_source, select_material_lights

    projectiles = [
        Projectile(active=True, type_id=PT.ION_CANNON, life_timer=0.4, origin=Vec2(-28, 300), pos=Vec2(228, 300))
        for _ in range(15)
    ]
    projectiles += [
        Projectile(active=True, type_id=PT.ION_MINIGUN, life_timer=life, origin=Vec2(-28, 100), pos=Vec2(228, 100))
        for life in (0.4, 0.36)
    ]

    def selected():
        return select_material_lights(
            [source for ident, projectile in enumerate(projectiles)
             if (source := projectile_source(projectile, ident)) is not None],
            view_center=Vec2(100, 100),
        )

    first = selected()
    assert len(first) == 17 and first[-2].illumination_gain > 0 and first[-1].illumination_gain == 0
    assert (first[-2].ident, first[-1].ident) == (15, 16)
    before, _ = prepare_beam_lights(first)
    projectiles[-2].life_timer, projectiles[-1].life_timer = 0.36, 0.4
    second = selected()
    # The brighter source takes the lit slot; the mask profile follows the slot, not the source.
    assert len(second) == 17 and second[-2].illumination_gain > 0 and second[-1].illumination_gain == 0
    assert (second[-2].ident, second[-1].ident) == (16, 15)
    after, _ = prepare_beam_lights(second)
    row_size = SOURCE_CELLS * 4
    for rows in (before, after):
        assert any(rows[15 * row_size : 16 * row_size]) and not any(rows[16 * row_size : 17 * row_size])
    assert prepare_beam_lights([]) == ([], [])
    nonbeam = MaterialLight(Vec2(), 100, (1, 1, 1), length=250)
    values, grid = prepare_beam_lights([nonbeam])
    assert not any(values) and grid == [nonbeam]


def test_full_section_extent_pads_only_beam_cell_lists() -> None:
    from crimson.render.rtx.reflection_occlusion import BodyVolume, build_occlusion_grid

    original = light()
    cells, grid_sources = prepare_beam_lights([original])
    margin = max(cells[2::4])
    assert margin > 4.0
    assert grid_sources[0].source_width == original.source_width
    assert grid_sources[0].length == original.length + 2 * 56 * 1.05 * SUPPORT
    assert original.source_width == 3 and original.length == 256
    bodies = [BodyVolume(Vec2(100, 90), Vec2(12, 9), 50, 0, opacity=0.5) for _ in range(384)]
    grid = build_occlusion_grid(bodies, grid_sources, width=256, height=256, beam_margin=margin)
    assert grid.body_count == len(bodies)
    # Section walks get the half-span; other lights keep the transverse margin.
    plain = build_occlusion_grid(bodies, grid_sources, width=256, height=256)
    assert grid.references == plain.references < grid.beam_references
    zero = msgspec.structs.replace(original, length=0, direction=Vec2())
    zero_cells, zero_grid = prepare_beam_lights([zero])
    assert zero_grid[0].direction == Vec2(1, 0)
    assert zero_grid[0].length > 0 and all(math.isfinite(value) for value in zero_cells)


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
        cells, grid_sources = prepare_beam_lights([source])
        assert all(math.isfinite(value) for value in cells)
        assert grid_sources[0].direction == source.direction
