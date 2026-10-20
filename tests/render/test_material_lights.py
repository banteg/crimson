from __future__ import annotations

from typing import Any, cast

import pytest

from crimson.creatures.runtime import CreaturePool
from crimson.projectiles.types import ProjectileTemplateId
from crimson.render.frame import RenderFrame
from crimson.render.rtx.material_lights import MAX_ILLUMINATION_SOURCES, MAX_MATERIAL_LIGHTS, collect_material_lights
from crimson.render.rtx.mode import RtxRenderMode
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2


def frame() -> RenderFrame:
    return RenderFrame(
        config=None, camera=Vec2(), ground=None, state=GameplayState(),
        players=[PlayerState(index=0, pos=Vec2(0, 0)), PlayerState(index=1, pos=Vec2(900, 0))],
        creatures=CreaturePool(), resources=cast(Any, None), elapsed_ms=0, bonus_anim_phase=0, rtx_mode=RtxRenderMode.RTX,
    )


def test_light_budget_follows_view_not_player_order() -> None:
    snapshot = frame()
    for i, projectile in enumerate(snapshot.state.projectiles.entries[:MAX_MATERIAL_LIGHTS * 2]):
        projectile.active = True
        projectile.type_id = ProjectileTemplateId.PLASMA_RIFLE
        projectile.life_timer = .4
        projectile.pos = Vec2(10 * i, 0)
    right = collect_material_lights(snapshot, view_center=Vec2(900, 0))
    snapshot.players.reverse()
    assert collect_material_lights(snapshot, view_center=Vec2(900, 0)) == right
    left = collect_material_lights(snapshot, view_center=Vec2(0, 0))
    assert len(right) == len(left) == MAX_ILLUMINATION_SOURCES
    assert min(light.pos.x for light in right) > max(light.pos.x for light in left)


def test_muzzle_radiance_fades_linearly() -> None:
    snapshot = frame()
    player = snapshot.players[0]
    player.muzzle_flash_alpha = 1
    bright = collect_material_lights(snapshot, view_center=Vec2())[0]
    player.muzzle_flash_alpha = .5
    faded = collect_material_lights(snapshot, view_center=Vec2())[0]
    assert faded.rgb == pytest.approx(tuple(channel * .5 for channel in bright.rgb))


@pytest.mark.parametrize("kind, height", [(ProjectileTemplateId.ION_RIFLE, 24.), (ProjectileTemplateId.PLASMA_RIFLE, 18.)])
def test_projectile_uses_one_height_for_illumination_and_reflection(kind, height) -> None:
    snapshot = frame()
    projectile = snapshot.state.projectiles.entries[0]
    projectile.active = True
    projectile.type_id = kind
    projectile.life_timer = .4
    projectile.origin = Vec2(10, 20)
    projectile.pos = Vec2(110, 20)
    light = collect_material_lights(snapshot, view_center=Vec2(60, 20))[0]
    assert light.height == height
    assert light.length == (100 if kind == ProjectileTemplateId.ION_RIFLE else 17.5)


def test_reflection_only_tracers_survive_full_illumination_budget() -> None:
    from crimson.render.rtx.material_lights import MaterialLight, select_material_lights

    lamps = [MaterialLight(Vec2(i, 0), 200, (2, 1, .5), reflection_gain=0) for i in range(20)]
    tracers = [MaterialLight(Vec2(i, 0), 50, (.1, .1, .1), illumination_gain=0) for i in range(20)]
    selected = select_material_lights(lamps + tracers, view_center=Vec2())
    assert len(selected) == MAX_MATERIAL_LIGHTS
    assert sum(s.illumination_gain > 0 for s in selected) == 16
    assert sum(s.reflection_gain > 0 for s in selected) == 16
    assert all(not (s.illumination_gain and s.reflection_gain) for s in selected)


def test_source_union_masks_unselected_response_without_double_counting() -> None:
    from crimson.render.rtx.material_lights import MaterialLight, select_material_lights

    shared = MaterialLight(Vec2(), 200, (4, 4, 4))
    lamps = [MaterialLight(Vec2(), 200, (2, 2, 2), reflection_gain=.001) for _ in range(20)]
    mirrors = [MaterialLight(Vec2(), 200, (.5, .5, .5), illumination_gain=.001) for _ in range(20)]
    selected = select_material_lights([shared, *lamps, *mirrors], view_center=Vec2())
    assert selected[0] == shared
    assert selected.count(shared) == 1
    assert len(selected) == 31
    assert all(s.reflection_gain == 0 for s in selected[1:16])
    assert all(s.illumination_gain == 0 for s in selected[16:])


def test_long_segment_is_ranked_by_nearest_point_not_midpoint() -> None:
    from crimson.render.rtx.material_lights import MaterialLight, select_material_lights

    beam = MaterialLight(Vec2(5000, 0), 100, (1, 1, 1), direction=Vec2(1, 0), length=10000)
    competitors = [MaterialLight(Vec2(200, 0), 100, (1, 1, 1)) for _ in range(20)]
    assert beam in select_material_lights([*competitors, beam], view_center=Vec2())


@pytest.mark.parametrize("kind", [ProjectileTemplateId.PISTOL, ProjectileTemplateId.ASSAULT_RIFLE,
                                  ProjectileTemplateId.SHOTGUN, ProjectileTemplateId.SUBMACHINE_GUN])
def test_ballistic_tracers_reflect_without_illuminating(kind) -> None:
    from crimson.projectiles.types import Projectile
    from crimson.render.rtx.material_lights import projectile_source

    source = projectile_source(Projectile(active=True, type_id=kind, life_timer=.4,
                                         origin=Vec2(), pos=Vec2(200, 0)))
    assert source is not None
    assert source.illumination_gain == 0
    assert source.reflection_gain > 0
    assert 0 < source.source_width < 1
    assert source.length == 200


def test_gauss_optical_fade_is_quieter_and_faster_without_mutating_lifetime() -> None:
    import msgspec

    from crimson.projectiles.types import Projectile
    from crimson.render.rtx.material_lights import projectile_source

    projectile = Projectile(active=True, type_id=ProjectileTemplateId.GAUSS_GUN, life_timer=.4,
                            origin=Vec2(), pos=Vec2(500, 0))
    before = msgspec.to_builtins(projectile)
    bright = projectile_source(projectile)
    assert msgspec.to_builtins(projectile) == before
    faded = projectile_source(msgspec.structs.replace(projectile, life_timer=.2))
    assert bright is not None and faded is not None
    assert bright.length == 500
    assert max(bright.rgb) < .2
    assert bright.illumination_gain < .2
    assert max(faded.rgb) / max(bright.rgb) == pytest.approx(.5**2.2)


@pytest.mark.parametrize("kind,width,tail", [(ProjectileTemplateId.PLASMA_MINIGUN, 2, 4.2),
                                             (ProjectileTemplateId.PLASMA_RIFLE, 5, 17.5),
                                             (ProjectileTemplateId.PLASMA_CANNON, 9, 44.2)])
def test_plasma_source_matches_warm_atlas_and_changes_shape_at_impact(kind, width, tail) -> None:
    import math

    from crimson.projectiles.types import Projectile
    from crimson.render.rtx.material_lights import projectile_source

    projectile = Projectile(active=True, type_id=kind, life_timer=.4, angle=math.pi/2,
                            origin=Vec2(), pos=Vec2(200, 0), speed_scale=2)
    flight = projectile_source(projectile)
    assert flight is not None
    assert flight.rgb[0] > flight.rgb[1] > flight.rgb[2]
    assert flight.source_width == width
    assert flight.length == pytest.approx(tail*2)
    assert flight.pos.x + flight.length/2 == pytest.approx(200)
    projectile.life_timer = .2
    impact = projectile_source(projectile)
    assert impact is not None and impact.length == 0 and impact.source_width == 5
    assert impact.pos == projectile.pos
    assert impact.rgb[0] > impact.rgb[1] > impact.rgb[2]


def test_muzzle_matches_visible_flash_flags_and_warm_art() -> None:
    from crimson.weapons import WeaponId

    snapshot = frame()
    del snapshot.players[1:]
    player = snapshot.players[0]
    player.muzzle_flash_alpha = 1
    player.weapon.weapon_id = WeaponId.ION_RIFLE  # Native sprite suppressed by flag 8.
    assert collect_material_lights(snapshot, view_center=Vec2()) == []
    player.weapon.weapon_id = WeaponId.GAUSS_GUN
    source = collect_material_lights(snapshot, view_center=Vec2())[0]
    assert source.rgb[0] > source.rgb[1] > source.rgb[2]
    assert source.illumination_gain < .2


def test_rocket_exhaust_and_expanding_detonation() -> None:
    from crimson.projectiles.types import SecondaryProjectile
    from crimson.projectiles.types import SecondaryProjectileTypeId as ST

    snapshot = frame()
    snapshot.players.clear()
    for kind in (ST.ROCKET, ST.HOMING_ROCKET, ST.ROCKET_MINIGUN):
        snapshot.state.secondary_projectiles.entries[0] = SecondaryProjectile(active=True, type_id=kind, pos=Vec2(50, 50))
        source = collect_material_lights(snapshot, view_center=Vec2())[0]
        assert source.pos != Vec2(50, 50)
        assert source.illumination_gain > 0 and source.reflection_gain > 0
    sec = SecondaryProjectile(active=True, type_id=ST.DETONATION, detonation_t=.1)
    snapshot.state.secondary_projectiles.entries[0] = sec
    small = collect_material_lights(snapshot, view_center=Vec2())[0]
    sec.detonation_t = .6
    large = collect_material_lights(snapshot, view_center=Vec2())[0]
    assert large.source_width > small.source_width
    assert max(large.rgb) < max(small.rgb)


def test_flame_stream_is_grouped_and_excludes_bubbles() -> None:
    from crimson.effects import Particle, ParticleStyleId

    snapshot = frame()
    snapshot.players.clear()
    for i in range(20):
        snapshot.state.particles.entries[i] = Particle(active=True, style_id=ParticleStyleId.FLAMETHROWER,
                                                     pos=Vec2(20+i, 20), color_a=.5)
    sources = collect_material_lights(snapshot, view_center=Vec2())
    assert len(sources) == 1
    assert 20 < sources[0].pos.x < 40
    assert max(sources[0].rgb) <= 1.8
    for particle in snapshot.state.particles.entries:
        particle.style_id = ParticleStyleId.BUBBLEGUN
    assert collect_material_lights(snapshot, view_center=Vec2()) == []


def test_annulus_budget_uses_circumference_instead_of_center() -> None:
    from crimson.render.rtx.material_lights import MaterialLight, select_material_lights

    ring = MaterialLight(Vec2(1000, 0), 30, (1, 1, 1), ring_radius=1000)
    lamps = [MaterialLight(Vec2(40, 0), 30, (.8, .8, .8)) for _ in range(32)]
    selected = select_material_lights([ring, *lamps], view_center=Vec2())
    assert ring in selected
    centered_lamps = [MaterialLight(ring.pos, 30, (.8, .8, .8)) for _ in range(32)]
    assert ring not in select_material_lights([ring, *centered_lamps], view_center=ring.pos)
