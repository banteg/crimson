from __future__ import annotations

import math

import msgspec
import pytest

from crimson.bonuses import BonusId
from crimson.bonuses.pool import BonusEntry
from crimson.creatures.runtime import CreatureState
from crimson.creatures.spawn import CreatureTypeId
from crimson.render.rtx.material_lights import MaterialLight
from crimson.render.rtx.reflection_occlusion import (
    CELL_SIZE,
    CROWD_BODIES,
    PENUMBRA_WIDTH,
    BodyVolume,
    bonus_body_volumes,
    build_occlusion_grid,
    creature_body_volumes,
    player_body_volumes,
)
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2


def test_body_profiles_rotate_and_scale_with_the_drawn_sprite() -> None:
    for species in CreatureTypeId:
        creature = CreatureState(active=True, hp=100, type_id=species, pos=Vec2(100, 200), size=50)
        bodies = creature_body_volumes(creature)
        if not bodies:
            continue
        assert len(bodies) == 1
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
        assert creature_body_volumes(creature) == doubled
        creature.death_timer = 0
        assert not creature_body_volumes(creature)
        creature.death_timer = 16
        creature.hp = 100
        creature.active = False
        assert not creature_body_volumes(creature)


def test_spatial_grid_keeps_overlaps_up_to_a_crowd_without_priority_truncation() -> None:
    bodies = [BodyVolume(Vec2(100, 100), Vec2(8, 14), 24, i * .01) for i in range(CROWD_BODIES)]
    light = MaterialLight(Vec2(100, 90), 100, (1, 1, 1), illumination_gain=0)

    def home_header(bodies):
        grid = build_occlusion_grid(bodies, [light], width=1024, height=1024)
        x = math.floor((100 - grid.origin.x) / grid.cell_size)
        y = math.floor((100 - grid.origin.y) / grid.cell_size)
        return grid, grid.values[(y * grid.columns + x) * 4:][:2]

    grid, (offset, count) = home_header(bodies)
    assert grid.body_count == count == CROWD_BODIES
    assert len({grid.values[(int(offset) + i) * 4] for i in range(int(count))}) == CROWD_BODIES
    assert build_occlusion_grid(bodies, [], width=1024, height=1024).body_count == 0


def header(grid, x: float, y: float) -> list[float]:
    column = math.floor((x - grid.origin.x) / grid.cell_size)
    row = math.floor((y - grid.origin.y) / grid.cell_size)
    return grid.values[(row * grid.columns + column) * 4:][:4]


def test_crowded_cell_holds_density_and_top_height_instead_of_its_list() -> None:
    light = MaterialLight(Vec2(100, 90), 100, (1, 1, 1), illumination_gain=0)
    tall, short = BodyVolume(Vec2(100, 100), Vec2(8, 14), 30, 0), BodyVolume(Vec2(110, 100), Vec2(8, 14), 10, 0, .5)
    grid = build_occlusion_grid([tall] * 200 + [short] * 200, [light], width=1024, height=1024)
    area = math.pi * 8 * 14 / grid.cell_size ** 2
    # Its members stand wholly inside it: none is uploaded.
    assert grid.body_count == 0
    assert header(grid, 100, 100) == pytest.approx([(30 * 200 + 10 * 100) / 300, -area * 300, 0, 0])


def test_crowd_follows_what_stands_in_a_cell_not_its_padded_lists() -> None:
    # The widest penumbra pads every body's lists by its width times the body's aspect ratio.
    light = MaterialLight(Vec2(100, 90), 400, (1, 1, 1), illumination_gain=0, source_width=PENUMBRA_WIDTH)
    area = math.pi * 8 * 14 / CELL_SIZE ** 2
    # Centered left of the cell edge at x = 128, reaching 4 units across it: it stands in both cells.
    straddling = BodyVolume(Vec2(124, 100), Vec2(8, 14), 24, 0)
    grid = build_occlusion_grid([straddling] * (CROWD_BODIES + 1), [light], width=1024, height=1024)
    assert header(grid, 124, 100) == pytest.approx([24, -area * (CROWD_BODIES + 1) * .75, 0, 0])
    assert header(grid, 130, 100) == pytest.approx([24, -area * (CROWD_BODIES + 1) * .25, 0, 0])
    # Standing short of the edge, only its padding reaches across: there a crowd's members are dropped, and the
    # cell stays a list.
    short = BodyVolume(Vec2(118, 100), Vec2(8, 14), 24, 0)
    grid = build_occlusion_grid([short] * (CROWD_BODIES + 1), [light], width=1024, height=1024)
    assert header(grid, 130, 100)[1] == header(grid, 130, 100)[3] == 0
    # One fewer is no crowd: every cell keeps its exact list.
    grid = build_occlusion_grid([short] * CROWD_BODIES, [light], width=1024, height=1024)
    assert header(grid, 130, 100)[1] == CROWD_BODIES


def test_source_culling_retains_long_tracer_and_rejects_distant_bodies() -> None:
    near = BodyVolume(Vec2(50, 50), Vec2(8, 14), 24, 0)
    far = BodyVolume(Vec2(50, 900), Vec2(8, 14), 24, 0)
    source = MaterialLight(Vec2(900, 50), 1, (1, 1, 1), direction=Vec2(1, 0), length=1800,
                           illumination_gain=0, reflection_radius=100)
    assert build_occlusion_grid([near, far], [source], width=1024, height=1024).body_count == 1



def test_sources_wider_than_the_penumbra_width_pad_no_further() -> None:
    bodies = [BodyVolume(Vec2(100 + 37 * i, 300), Vec2(4, 12), 24, 0) for i in range(12)]

    def references(width: float) -> int:
        light = MaterialLight(Vec2(300, 300), 400, (1, 1, 1), source_width=width)
        return build_occlusion_grid(bodies, [light], width=1024, height=1024).references

    assert references(2) < references(PENUMBRA_WIDTH) == references(PENUMBRA_WIDTH * 4)


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


def test_annulus_grid_keeps_outer_endpoints_and_interior_ray_blockers() -> None:
    ring = MaterialLight(Vec2(500, 500), 30, (1, 1, 1), ring_radius=450)
    bodies = [BodyVolume(Vec2(x, y), Vec2(8, 14), 24, 0)
              for x, y in [(500, 500), (60, 500), (940, 500), (500, 60), (500, 940)]]
    far = BodyVolume(Vec2(1500, 1500), Vec2(8, 14), 24, 0)
    grid = build_occlusion_grid([*bodies, far], [ring], width=64, height=64)
    assert grid.body_count == 5
    assert grid.origin.x + grid.columns * grid.cell_size >= 950
    assert grid.origin.y + grid.rows * grid.cell_size >= 950


def test_killed_visible_caster_collapses_with_native_timer_and_current_geometry() -> None:

    creature = CreatureState(active=True, hp=100, type_id=CreatureTypeId.SPIDER_SP1,
                             pos=Vec2(100, 200), size=60)
    living = creature_body_volumes(creature)
    creature.hp = 0
    assert creature_body_volumes(creature) == living  # No pop on the killing hit.
    last_height, last_opacity = living[0].height, living[0].opacity
    for timer in (15., 8., 4., 2., .1):
        creature.death_timer = timer
        volumes = creature_body_volumes(creature)
        assert 0 < volumes[0].height < last_height
        assert 0 < volumes[0].opacity <= last_opacity
        assert volumes[0].radii == living[0].radii
        last_height, last_opacity = volumes[0].height, volumes[0].opacity
    creature.death_timer = 8
    collapsed = creature_body_volumes(creature)
    creature.pos += Vec2(15, -8)
    moved = creature_body_volumes(creature)
    assert moved[0].pos == collapsed[0].pos + Vec2(15, -8)
    assert moved[0].owner == creature.pos
    creature.size *= .5
    shrunk = creature_body_volumes(creature)
    assert shrunk[0].radii == moved[0].radii * .5
    assert shrunk[0].height == moved[0].height * .5
    assert creature_body_volumes(msgspec.structs.replace(creature, active=False)) == []
    assert creature_body_volumes(msgspec.structs.replace(creature, size=0)) == []
    assert creature_body_volumes(msgspec.structs.replace(creature, tint=creature.tint.with_alpha(0))) == []
    # At baking, the ground material replaces the elevated caster. Fading sprite
    # overlays must not keep an invisible body volume above that baked corpse.
    for timer in (0., -.1, -5., -10., -11.):
        creature.death_timer = timer
        assert creature_body_volumes(creature) == []


def test_player_torso_turns_with_aim_scales_with_size_and_leaves_on_death() -> None:
    player = PlayerState(index=0, pos=Vec2(300, 400))
    (body,) = player_body_volumes(player)
    assert body.pos == body.owner == player.pos
    assert body.radii.x < body.radii.y  # Shoulders wider than deep.
    player.aim_heading += math.pi / 2
    (turned,) = player_body_volumes(player)
    assert turned.angle == pytest.approx(body.angle + math.pi / 2)
    player.size *= 2
    (grown,) = player_body_volumes(player)
    assert grown.radii == body.radii * 2
    assert grown.height == pytest.approx(body.height * 2)
    player.health = 0
    assert player_body_volumes(player) == []


def test_bonus_shell_follows_its_bubble_fade() -> None:
    bonus = BonusEntry(bonus_id=BonusId.POINTS, time_left=10., time_max=10., pos=Vec2(50, 60))
    assert bonus_body_volumes(bonus) == []  # Spawning: the shell has not faded in.
    bonus.time_left = 9.8
    (rising,) = bonus_body_volumes(bonus)
    bonus.time_left = 5.
    (full,) = bonus_body_volumes(bonus)
    assert 0 < rising.opacity < full.opacity == pytest.approx(.9)
    assert full.pos == full.owner == bonus.pos
    bonus.time_left = 1.
    (expiring,) = bonus_body_volumes(bonus)
    assert expiring.opacity < full.opacity
    assert expiring.radii == full.radii
    bonus.bonus_id = BonusId.UNUSED
    assert bonus_body_volumes(bonus) == []
