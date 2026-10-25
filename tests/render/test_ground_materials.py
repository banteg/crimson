from __future__ import annotations

import math
import struct
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

import msgspec
import pytest

from crimson.creatures.runtime import CreaturePool, CreatureState
from crimson.creatures.spawn import CreatureTypeId
from crimson.effects import FxQueueEntry, FxQueueRotatedEntry
from crimson.render.frame import RenderFrame
from crimson.render.rtx import materials as ground_materials
from crimson.render.rtx.debug import RtxDebugView
from crimson.render.rtx.material_lights import MaterialLight
from crimson.render.rtx.materials import MaterialGroundRenderer, _integer, _uniform
from crimson.render.rtx.mode import RtxRenderMode
from crimson.render.rtx.reflection_occlusion import BodyVolume
from crimson.render.terrain_fx import FxQueueTextures
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.terrain_fx import TerrainFxBatch
from crimson.world.render_resources import RenderResources
from grim.blend import opaque_blend
from grim.color import RGBA
from grim.edr import load_float_render_texture
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.terrain_stamps import TerrainLayers
from grim.texture_mode import texture_mode


def pixels(target: rl.RenderTexture) -> list[tuple[float, float, float, float]]:
    image = rl.load_image_from_texture(target.texture)
    try:
        rl.image_format(image, rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32)
        data = bytes(rl.ffi.buffer(image.data, image.width * image.height * 16))
        return list(struct.iter_unpack("ffff", data))
    finally:
        rl.unload_image(image)


@pytest.fixture
def ground_material(raylib_context):
    image = rl.gen_image_color(128, 128, rl.WHITE)
    texture = rl.load_texture_from_image(image)
    rl.unload_image(image)
    ground = MaterialGroundRenderer(texture, texture, texture, width=64, height=64)
    ground.schedule_stamps(TerrainLayers(base=(), overlay=(), detail=()), texture_scale=1)
    ground.process_pending()
    try:
        yield ground, texture
    finally:
        ground.close()
        rl.unload_texture(texture)


def blood(time: float) -> TerrainFxBatch:
    return TerrainFxBatch(
        decals=(FxQueueEntry(effect_id=7, pos=Vec2(32, 32), width=32, height=32, color=RGBA(1, 0, 0, 1)),),
        elapsed_s=time,
    )


def test_lazy_materials_order_volume_clock_and_no_diffuse_bevel(ground_material) -> None:
    ground, texture = ground_material
    assert ground.surface is None and ground.coverage is None and ground.material_shader is None
    albedo = pixels(ground.render_target)
    ground.material_batches.append(blood(1200.25))
    ground.bake_materials(texture, texture)
    assert ground.surface is not None and ground.coverage is not None
    n = ground.surface.texture.width
    center = (n // 2) * n + n // 2
    dry = pixels(ground.surface)[0]
    first = pixels(ground.surface)[center]
    assert first[1] / first[2] == pytest.approx(1.)
    assert 0.3 < first[2] < 0.7
    # Blood leaves the entire substrate height field untouched, including its boundaries.
    assert {p[3] for p in pixels(ground.surface)} == {dry[3]}
    assert pixels(ground.coverage)[center][:3] == pytest.approx((1, 0, 0))
    ground.material_batches.append(blood(1202.5))
    ground.bake_materials(texture, texture)
    second = pixels(ground.surface)[center]
    assert second[2] > first[2]
    assert math.exp(-(1202.5 - ground.wetness_epoch) / 45) * second[1] / second[2] == pytest.approx(
        (second[2] - first[2] * (1 - first[2]) * (1 - math.exp(-2.25 / 45))) / second[2],
    )
    corpse = TerrainFxBatch(
        corpses=(FxQueueRotatedEntry(top_left=Vec2(16, 16), scale=32, color=RGBA(1, 1, 1, 1), creature_type_id=0),),
    )
    ground.material_batches.append(corpse)
    ground.bake_materials(texture, texture)
    assert pixels(ground.coverage)[center][:3] == pytest.approx((0, 1, 0))
    assert pixels(ground.surface)[center][2] == 0
    ground.material_batches.append(blood(1300))
    ground.bake_materials(texture, texture)
    assert pixels(ground.coverage)[center][:3] == pytest.approx((1, 0, 0))
    last = pixels(ground.surface)[center]
    assert math.exp(-(1300 - ground.wetness_epoch) / 45) * last[1] / last[2] == pytest.approx(1.)
    # Baking companions must never change the classic albedo target.
    assert pixels(ground.render_target) == albedo


def test_fresh_blood_reflects_hdr_then_dries(ground_material) -> None:
    ground, texture = ground_material
    ground.material_batches.extend([blood(1200)] * 6)
    ground.bake_materials(texture, texture)
    sh = ground.material_shader
    assert sh is not None and ground.surface is not None and ground.coverage is not None
    target = load_float_render_texture(64, 64)
    try:
        _uniform(sh, "u_ground_size", [64, 64])
        _integer(sh, "u_spec_light_count", 1)
        _uniform(sh, "u_spec_pos[0]", [32, 14, 150, 30])
        _uniform(sh, "u_spec_color[0]", [4, 4, 4, 0])
        _uniform(sh, "u_spec_dir[0]", [0, 0, 0, 0])
        _uniform(sh, "u_spec_response[0]", [1, 1, 150, 3])
        values = []
        for time in (1200, 1290):
            _uniform(sh, "u_time_s", [time - ground.wetness_epoch])
            with texture_mode(target), opaque_blend():
                rl.begin_shader_mode(sh)
                try:
                    rl.set_shader_value_texture(sh, rl.get_shader_location(sh, "u_surface_tex"), ground.surface.texture)
                    rl.set_shader_value_texture(
                        sh,
                        rl.get_shader_location(sh, "u_material_tex"),
                        ground.coverage.texture,
                    )
                    rl.set_shader_value_texture(
                        sh, rl.get_shader_location(sh, "u_substrate_tex"), ground.substrate.render_target.texture,
                    )
                    ground.draw_view(Vec2(), screen_w=64, screen_h=64, out_w=64, out_h=64)
                finally:
                    rl.end_shader_mode()
            values.append(pixels(target)[32 * 64 + 32])
        assert max(values[0][:3]) > 1.0  # no intermediate SDR clipping
        assert max(values[1][:3]) < max(values[0][:3]) * 0.8
    finally:
        rl.unload_render_texture(target)


def test_material_resources_close_and_regenerate(ground_material) -> None:
    ground, texture = ground_material
    ground.material_batches.append(blood(10))
    ground.bake_materials(texture, texture)
    ground.schedule_stamps(TerrainLayers(base=(), overlay=(), detail=()), texture_scale=2)
    ground.process_pending()
    assert ground.surface is None and ground.coverage is None and not ground.material_batches
    ground.bake_materials(texture, texture)
    assert ground.surface.texture.width == ground.render_target.texture.width
    resources = RenderResources(assets_dir=Path("."), ground=ground)
    resources.close()
    resources.close()
    assert ground.surface is None and ground.coverage is None and ground.substrate is None
    assert ground.stamp_shader is None and ground.material_shader is None and ground.render_target is None


def test_real_material_scope_keeps_auxiliary_samplers_across_ground_blend_switch(ground_material, mocker) -> None:
    ground, texture = ground_material
    ground.material_batches.extend([blood(900)] * 6)

    class Textures:
        def texture(self, _texture_id):
            return texture

    frame = RenderFrame(
        config=None,
        camera=Vec2(),
        ground=ground,
        state=GameplayState(),
        players=[],
        creatures=CreaturePool(),
        resources=cast(Any, Textures()),
        elapsed_ms=900000,
        bonus_anim_phase=0,
        rtx_mode=RtxRenderMode.RTX,
    )
    mocker.patch.object(
        ground_materials, "collect_material_lights",
        return_value=[MaterialLight(Vec2(32, 14), 150, (4, 4, 4), height=30)],
    )
    target = load_float_render_texture(64, 64)
    try:
        # Start in normal alpha blending, exactly like draw_background (no outer opaque helper).
        with texture_mode(target), ground.material_scope(frame):
            ground.draw_view(Vec2(), screen_w=64, screen_h=64, out_w=64, out_h=64)
        assert max(pixels(target)[32 * 64 + 32][:3]) > 1.0
    finally:
        rl.unload_render_texture(target)


def test_clean_substrate_avoids_double_blood_tint_and_rebuild_matches(ground_material) -> None:
    ground, texture = ground_material
    resources = RenderResources(assets_dir=Path("."), ground=ground, fx_textures=FxQueueTextures(texture, texture))
    before = pixels(ground.render_target)
    resources.bake_terrain_fx_batch(blood(300), ground)
    assert pixels(ground.render_target) != before  # original red sprite is still baked for classic
    history = list(ground.material_batches)
    ground.bake_materials(texture, texture)
    assert not ground.material_batches
    assert pixels(ground.substrate.render_target) == before
    surface, coverage = pixels(ground.surface), pixels(ground.coverage)
    ground.reset_materials()
    ground.material_batches.extend(history)
    ground.bake_materials(texture, texture)
    assert pixels(ground.surface) == surface
    assert pixels(ground.coverage) == coverage
    assert pixels(ground.substrate.render_target) == before


@pytest.mark.parametrize("effect_id", [7, 18, 8])
def test_fresh_soft_edges_and_nonblood_materials_do_not_age_with_match_clock(ground_material, mocker, effect_id) -> None:
    ground, texture = ground_material

    class Textures:
        def texture(self, _texture_id):
            return texture

    frame = RenderFrame(
        config=None,
        camera=Vec2(),
        ground=ground,
        state=GameplayState(),
        players=[],
        creatures=CreaturePool(),
        resources=cast(Any, Textures()),
        elapsed_ms=0,
        bonus_anim_phase=0,
        rtx_mode=RtxRenderMode.RTX,
    )
    mocker.patch.object(
        ground_materials, "collect_material_lights",
        return_value=[MaterialLight(Vec2(32, 14), 150, (4, 4, 4), height=30)],
    )
    target = load_float_render_texture(67, 67)  # nonintegral sampling exercises filtering at empty edges
    renders = []
    try:
        for time in (0.0, 36000.25):
            ground.reset_materials()
            batch = blood(time)
            entry = msgspec.structs.replace(batch.decals[0], effect_id=effect_id, color=RGBA(1, 0, 0, 0.1))
            ground.material_batches.append(msgspec.structs.replace(batch, decals=(entry,)))
            with texture_mode(target), ground.material_scope(msgspec.structs.replace(frame, elapsed_ms=time * 1000)):
                ground.draw_view(Vec2(), screen_w=64, screen_h=64, out_w=67, out_h=67)
            renders.append(pixels(target))
        assert renders[1] == renders[0]
    finally:
        rl.unload_render_texture(target)


def test_partial_scorch_removes_film_without_diluting_its_age(ground_material) -> None:
    ground, texture = ground_material
    ground.material_batches.append(blood(1200))
    ground.bake_materials(texture, texture)
    n = ground.surface.texture.width
    center = n // 2 * n + n // 2
    before = pixels(ground.surface)[center]
    scorch = msgspec.structs.replace(blood(1250).decals[0], effect_id=16, color=RGBA(0, 0, 0, 0.5))
    ground.material_batches.append(TerrainFxBatch(decals=(scorch,), elapsed_s=1250))
    ground.bake_materials(texture, texture)
    after = pixels(ground.surface)[center]
    assert after[2] < before[2] * 0.6
    assert after[1] / after[2] == pytest.approx(before[1] / before[2])
    assert pixels(ground.coverage)[center][0] < 0.6


def debug_pixels(ground, texture, *, mode: int, time: float = 0, creatures: CreaturePool | None = None, shadows: bool = True, pixel_format: int | None = None, live: bool = False) -> list[tuple[float, float, float, float]]:
    class Textures:
        def texture(self, _texture_id):
            return texture

    from grim.config import default_crimson_cfg
    config = default_crimson_cfg()
    config.display.shadows_enabled = shadows
    frame = RenderFrame(
        config=config, camera=Vec2(), ground=ground, state=GameplayState(), players=[], creatures=creatures if creatures is not None else CreaturePool(),
        resources=cast(Any, Textures()), elapsed_ms=time * 1000, bonus_anim_phase=0, rtx_mode=RtxRenderMode.RTX,
        rtx_debug=RtxDebugView(mode) if live else RtxDebugView.SHADED,
    )
    target = load_float_render_texture(64, 64, **({"pixel_format": pixel_format} if pixel_format is not None else {}))
    try:
        with texture_mode(target), ground.material_scope(frame, debug=None if live else mode):
            ground.draw_view(Vec2(), screen_w=64, screen_h=64, out_w=64, out_h=64)
        return pixels(target)
    finally:
        rl.unload_render_texture(target)


def test_shader_substrate_normal_is_independent_of_blood_depth(ground_material) -> None:
    ground, texture = ground_material
    ground.bake_materials(texture, texture)
    # A raised nonblood patch makes this a meaningful normal test, not a flat-field identity.
    ground.material_batches.append(TerrainFxBatch(corpses=(
        FxQueueRotatedEntry(top_left=Vec2(16, 16), scale=20, color=RGBA(1, 1, 1, 1)),
    )))
    before = debug_pixels(ground, texture, mode=1)
    assert len(set(before)) > 1
    ground.material_batches.extend([blood(0)] * 8)
    after = debug_pixels(ground, texture, mode=1)
    assert after == before  # Samples actual N_sub, including pool boundaries.


def test_shader_meniscus_requires_deep_blood_not_just_sprite_coverage(ground_material) -> None:
    ground, texture = ground_material
    # Repeated faint mist saturates coverage before it accumulates much liquid.
    entry = msgspec.structs.replace(blood(0).decals[0], color=RGBA(1, 0, 0, .1))
    ground.material_batches.extend([TerrainFxBatch(decals=(entry,))] * 6)
    thin = debug_pixels(ground, texture, mode=2)
    # The broad transition permits tiny slopes, but must not outline mist like a deep pool.
    assert all(p[:3] == pytest.approx((.5, .5, 1.), abs=.001) for p in thin)
    amount = debug_pixels(ground, texture, mode=4)
    assert 0 < max(p[0] for p in amount) < .38
    ground.material_batches.extend([blood(0)] * 8)
    deep = debug_pixels(ground, texture, mode=2)
    assert any(abs(p[0] - .5) > .01 or abs(p[1] - .5) > .01 for p in deep)


def test_faint_spray_refreshes_only_its_share_of_an_old_pool(ground_material) -> None:
    ground, texture = ground_material
    ground.material_batches.extend([blood(0)] * 8)
    dry = debug_pixels(ground, texture, mode=3, time=36000.25)
    center = 32 * 64 + 32
    assert dry[center][0] == 0
    thin = msgspec.structs.replace(blood(36000.25).decals[0], color=RGBA(1, 0, 0, .1))
    ground.material_batches.append(TerrainFxBatch(decals=(thin,), elapsed_s=36000.25))
    mixed = debug_pixels(ground, texture, mode=3, time=36000.25)
    assert .02 < mixed[center][0] < .1
    ground.reset_materials()
    ground.material_batches.append(TerrainFxBatch(decals=(thin,), elapsed_s=36000.25))
    fresh = debug_pixels(ground, texture, mode=3, time=36000.25)
    aged = debug_pixels(ground, texture, mode=3, time=36045.25)
    assert fresh[center][0] == pytest.approx(1.)
    assert aged[center][0] == pytest.approx(math.exp(-1), abs=.001)


def test_pass_major_stamps_match_incremental_mixed_decal_order(ground_material) -> None:
    ground, texture = ground_material
    batches = []
    for i in range(9):
        entries = tuple(msgspec.structs.replace(
            blood(0).decals[0], effect_id=kind, color=RGBA(0 if kind == 16 else 1, 0, 0, .6),
            pos=Vec2(25 + i, 25 + i), rotation=i * .1,
        ) for kind in (3, 4, 7, 8, 18, 16, 7))
        corpses = (FxQueueRotatedEntry(top_left=Vec2(20, 20), scale=18, color=RGBA(1, 1, 1, .6)),) if i % 2 else ()
        batches.append(TerrainFxBatch(decals=entries, corpses=corpses, elapsed_s=100 + i))
    ground.material_batches.extend(batches)
    ground.bake_materials(texture, texture)
    expected = [pixels(t) for t in (ground.surface, ground.coverage, ground.substrate.render_target)]
    ground.reset_materials()
    for batch in batches:
        ground.material_batches.append(batch)
        ground.bake_materials(texture, texture)
        assert not ground.material_batches
    actual = [pixels(t) for t in (ground.surface, ground.coverage, ground.substrate.render_target)]
    assert actual == expected


def test_shader_treats_emitter_rgb_as_linear_radiance(ground_material, mocker) -> None:
    ground, texture = ground_material
    ground.material_batches.extend([blood(0)] * 6)
    collector = mocker.patch.object(ground_materials, "collect_material_lights")
    values = []
    for intensity in (1, 2, 3):
        collector.return_value = [MaterialLight(Vec2(32, 14), 150, (intensity, intensity, intensity), height=30)]
        encoded = debug_pixels(ground, texture, mode=0)[32 * 64 + 32]
        values.append(tuple(channel ** 2.2 for channel in encoded[:3]))
    assert tuple(c - b for b, c in zip(values[1], values[2], strict=True)) == pytest.approx(
        tuple(b - a for a, b in zip(values[0], values[1], strict=True)), rel=.015,
    )


def uniform_fresh_film(ground, texture) -> None:
    ground.bake_materials(texture, texture)
    # Flat, uniform film isolates absorption from relief and meniscus effects.
    with texture_mode(ground.surface):
        rl.clear_background(rl.Color(10, 102, 102, 115))
    with texture_mode(ground.coverage):
        rl.clear_background(rl.Color(128, 0, 0, 0))


def test_weak_light_cannot_darken_ambient_blood_or_create_a_boundary_ring(ground_material, mocker) -> None:
    ground, texture = ground_material
    uniform_fresh_film(ground, texture)
    collector = mocker.patch.object(ground_materials, "collect_material_lights", return_value=[])
    center = 32 * 64 + 32
    baseline = debug_pixels(ground, texture, mode=0)[center][:3]
    rgb = (.62, .92, 1.4)
    # Cross the former normal_weight=0.001 branch with an almost extinguished light.
    crossing = 175 * (1 - math.sqrt(.001 / (sum(rgb) * .333)))
    values = []
    for distance in (crossing - .002, crossing + .002, 175, 175.01):
        collector.return_value = [MaterialLight(Vec2(32.5 + distance, 31.5), 175, rgb, height=18)]
        value = debug_pixels(ground, texture, mode=0)[center][:3]
        assert all(channel >= ambient - .0001 for channel, ambient in zip(value, baseline, strict=True))
        values.append(value)
    assert values[0] == pytest.approx(values[1], abs=.0002)
    assert values[-1] == baseline


def test_each_light_adds_its_own_absorbed_radiance(ground_material, mocker) -> None:
    ground, texture = ground_material
    uniform_fresh_film(ground, texture)
    collector = mocker.patch.object(ground_materials, "collect_material_lights")
    high = MaterialLight(Vec2(32, 32), 175, (.8, .7, .6), height=40)
    low = MaterialLight(Vec2(112, 32), 175, (.4, .9, 1.4), height=18)
    values = []
    for lights in ([], [high], [low], [high, low]):
        collector.return_value = lights
        encoded = debug_pixels(ground, texture, mode=0)[32 * 64 + 32][:3]
        values.append(tuple(channel ** 2.2 for channel in encoded))
    expected = tuple(a + b - ambient for ambient, a, b in zip(*values[:3], strict=True))
    assert values[3] == pytest.approx(expected, rel=.004, abs=.0001)


def test_single_expired_freeze_shard_has_ice_coverage_and_reflection(ground_material, mocker) -> None:
    from crimson.effects import EffectPool, FxQueue
    from grim.rand import Crand

    ground, texture = ground_material
    pool, queue = EffectPool(), FxQueue()
    pool.spawn_freeze_shard(pos=Vec2(32, 32), angle=0, rng=Crand(0), detail_preset=5, preserve_bugs=False)
    pool.update(1, fx_queue=queue)
    assert queue.count == 1
    shard = queue.iter_active()[0]
    assert shard.color.a == pytest.approx(.35)
    ground.material_batches.append(TerrainFxBatch(decals=(shard,)))
    ground.bake_materials(texture, texture)
    coverage = pixels(ground.coverage)
    assert max(pixel[3] for pixel in coverage) == pytest.approx(shard.color.to_rl().a / 255, abs=1 / 255)
    mocker.patch.object(ground_materials, "collect_material_lights", return_value=[
        MaterialLight(Vec2(32, 14), 150, (4, 4, 4), height=30),
    ])
    icy = debug_pixels(ground, texture, mode=5)
    # Remove only ice coverage: substrate color, relief, specularity and lights stay identical.
    with texture_mode(ground.coverage):
        rl.rl_color_mask(False, False, False, True)
        try:
            rl.clear_background(rl.BLANK)
        finally:
            rl.rl_color_mask(True, True, True, True)
    dry = debug_pixels(ground, texture, mode=5)
    assert max(max(a[:3]) - max(b[:3]) for a, b in zip(icy, dry, strict=True)) > .01


@pytest.mark.parametrize("kind", [7, 16, 18, None])
def test_later_deposits_cover_ice_in_order(ground_material, kind) -> None:
    ground, texture = ground_material
    ice = msgspec.structs.replace(blood(0).decals[0], effect_id=8, color=RGBA(1, 1, 1, .35))
    ground.material_batches.append(TerrainFxBatch(decals=(ice,)))
    ground.bake_materials(texture, texture)
    n = ground.coverage.texture.width
    center = n // 2 * n + n // 2
    before = pixels(ground.coverage)[center][3]
    assert before > .3
    if kind is None:
        batch = TerrainFxBatch(corpses=(
            FxQueueRotatedEntry(top_left=Vec2(16, 16), scale=32, color=RGBA(1, 1, 1, .5)),
        ))
    else:
        entry = msgspec.structs.replace(ice, effect_id=kind, color=RGBA(0, 0, 0, .5))
        batch = TerrainFxBatch(decals=(entry,))
    ground.material_batches.append(batch)
    ground.bake_materials(texture, texture)
    assert pixels(ground.coverage)[center][3] == pytest.approx(before * .5, abs=2 / 255)


def test_translucent_ice_occludes_blood_without_cutting_a_liquid_meniscus(ground_material) -> None:
    ground, texture = ground_material
    uniform_fresh_film(ground, texture)
    with texture_mode(ground.surface):
        rl.clear_background(rl.Color(10, 204, 204, 115))
    with texture_mode(ground.coverage):
        rl.clear_background(rl.Color(255, 0, 0, 0))
    before = debug_pixels(ground, texture, mode=4)
    ice = msgspec.structs.replace(blood(0).decals[0], effect_id=8, color=RGBA(1, 1, 1, .35))
    ground.material_batches.append(TerrainFxBatch(decals=(ice,)))
    ground.bake_materials(texture, texture)
    after = debug_pixels(ground, texture, mode=4)
    # Coverage hides the film without changing its optical depth, including filtered edges.
    assert max(abs(a[0] - b[0]) for a, b in zip(before, after, strict=True)) < .005
    # Remove the legitimate raised-ice relief to isolate spurious liquid-outline normals.
    with texture_mode(ground.surface):
        rl.rl_color_mask(False, False, False, True)
        try:
            rl.clear_background(rl.Color(0, 0, 0, 115))
        finally:
            rl.rl_color_mask(True, True, True, True)
    normals = debug_pixels(ground, texture, mode=2)
    assert all(p[:3] == pytest.approx((.5, .5, 1.), abs=.001) for p in normals)


def test_ice_color_is_not_absorbed_by_older_blood_but_new_blood_can_cover_it(ground_material) -> None:
    ground, texture = ground_material
    ground.material_batches.extend([blood(0)] * 8)
    ground.bake_materials(texture, texture)
    image = rl.gen_image_color(128, 128, rl.Color(70, 170, 255, 255))
    icy_texture = rl.load_texture_from_image(image)
    rl.unload_image(image)
    center = 32 * 64 + 32
    try:
        underlying = debug_pixels(ground, texture, mode=0)[center]
        ice = msgspec.structs.replace(blood(0).decals[0], effect_id=8, color=RGBA(1, 1, 1, .35))
        ground.material_batches.append(TerrainFxBatch(decals=(ice,)))
        ground.bake_materials(icy_texture, texture)
        blue = debug_pixels(ground, texture, mode=0)[center]
        # The shard is translucent: bright fresh blood can remain visible through it.
        # Its blue contribution must survive absorption rather than become a red cutout.
        assert blue[2] > underlying[2] * 1.35
        assert blue[2] / blue[0] > underlying[2] / underlying[0] + .25
        ground.material_batches.extend([blood(1)] * 8)
        red = debug_pixels(ground, texture, mode=0, time=1)[center]
        assert red[0] > red[2]
        assert red[2] == pytest.approx(underlying[2], abs=.01)
        n = ground.coverage.texture.width
        assert pixels(ground.coverage)[n // 2 * n + n // 2][3] == 0
    finally:
        rl.unload_texture(icy_texture)


def uniform_deep_film(ground, texture) -> None:
    uniform_fresh_film(ground, texture)
    with texture_mode(ground.surface):
        rl.clear_background(rl.Color(10, 230, 230, 115))
    with texture_mode(ground.coverage):
        rl.clear_background(rl.Color(255, 0, 0, 0))


@pytest.mark.parametrize("length", [0., 28.])
def test_reflection_is_below_source_and_preserves_point_or_beam_shape(ground_material, mocker, length) -> None:
    ground, texture = ground_material
    uniform_deep_film(ground, texture)
    mocker.patch.object(ground_materials, "collect_material_lights", return_value=[
        MaterialLight(Vec2(32, 16), 150, (1, 1, 1), height=18, direction=Vec2(1, 0), length=length),
    ])
    rendered = debug_pixels(ground, texture, mode=5)
    energy = sum(p[0] for p in rendered)
    assert energy > 1
    # Readback starts at the bottom; convert it back to top-down world coordinates.
    center_y = sum((63.5 - i // 64) * p[0] for i, p in enumerate(rendered)) / energy
    assert center_y == pytest.approx(16 + 18 * math.tan(math.pi / 6), abs=.15)
    center_x = sum((i % 64 + .5) * p[0] for i, p in enumerate(rendered)) / energy
    var_x = sum((i % 64 + .5 - center_x) ** 2 * p[0] for i, p in enumerate(rendered)) / energy
    var_y = sum((63.5 - i // 64 - center_y) ** 2 * p[0] for i, p in enumerate(rendered)) / energy
    if length:
        assert var_x > var_y * 4
        assert center_x > 34  # The beam head remains brighter than the tail.
    else:
        assert var_x == pytest.approx(var_y, rel=.01)
        assert center_x == pytest.approx(32, abs=.01)


def test_degenerate_beam_direction_uses_finite_point_reflection(ground_material, mocker) -> None:
    ground, texture = ground_material
    uniform_deep_film(ground, texture)
    collector = mocker.patch.object(ground_materials, "collect_material_lights")
    images = []
    for length in (0., 28.):
        collector.return_value = [MaterialLight(Vec2(32, 16), 150, (1, 1, 1), height=18, length=length)]
        images.append(debug_pixels(ground, texture, mode=5))
    assert images[0] == images[1]
    assert all(math.isfinite(channel) for pixel in images[1] for channel in pixel)
    assert max(p[0] for p in images[1]) > .1


def test_fresh_deep_blood_has_red_body_and_loses_color_and_reflection_with_age(ground_material, mocker) -> None:
    ground, texture = ground_material
    uniform_deep_film(ground, texture)
    collector = mocker.patch.object(ground_materials, "collect_material_lights", return_value=[])
    colors = [debug_pixels(ground, texture, mode=0, time=t)[32 * 64 + 32] for t in (0, 45, 180)]
    assert colors[0][0] > colors[2][0] * 1.3
    assert colors[0][0] > colors[0][2] * 1.3
    assert colors[0][0] > colors[1][0] > colors[2][0]
    collector.return_value = [MaterialLight(Vec2(32, 16), 150, (1, 1, 1), height=18)]
    peaks = [max(p[0] for p in debug_pixels(ground, texture, mode=5, time=t)) for t in (0, 45, 180)]
    assert peaks[0] > peaks[1] > peaks[2]
    assert peaks[2] < peaks[0] * .25


def test_reflection_gain_and_reach_are_independent_of_illumination(ground_material, mocker) -> None:
    ground, texture = ground_material
    uniform_deep_film(ground, texture)
    collector = mocker.patch.object(ground_materials, "collect_material_lights", return_value=[])
    ambient = debug_pixels(ground, texture, mode=0)
    source = MaterialLight(Vec2(32, 14), 1, (2, 1, .5), height=18,
                           illumination_gain=0, reflection_radius=150)
    collector.return_value = [source]
    reflection = debug_pixels(ground, texture, mode=5)
    assert max(p[0] for p in reflection) > .1
    assert debug_pixels(ground, texture, mode=0) != ambient
    collector.return_value = [msgspec.structs.replace(source, illumination_gain=1)]
    assert debug_pixels(ground, texture, mode=5) == reflection
    collector.return_value = [msgspec.structs.replace(source, reflection_gain=0)]
    assert max(p[0] for p in debug_pixels(ground, texture, mode=5)) == 0
    assert debug_pixels(ground, texture, mode=0) == ambient


def test_source_width_changes_reflection_footprint_without_diffuse_spill(ground_material, mocker) -> None:
    ground, texture = ground_material
    uniform_deep_film(ground, texture)
    collector = mocker.patch.object(ground_materials, "collect_material_lights")
    energies, spreads = [], []
    for width in (1., 6.):
        collector.return_value = [MaterialLight(Vec2(32, 16), 150, (1, 1, 1), source_width=width, illumination_gain=0)]
        image = debug_pixels(ground, texture, mode=5)
        energy = sum(p[0] for p in image)
        energies.append(energy)
        spreads.append(sum(((i%64+.5)-32)**2*p[0] for i,p in enumerate(image))/energy)
    assert energies[1] > energies[0] * 2
    assert spreads[1] > spreads[0] * 2


def test_long_tracer_reflection_is_not_clipped_by_head_biased_illumination(ground_material, mocker) -> None:
    ground, texture = ground_material
    uniform_deep_film(ground, texture)
    # The head is outside this small tile. The visible tail still crosses the wet film.
    mocker.patch.object(ground_materials, "collect_material_lights", return_value=[
        MaterialLight(Vec2(1000, 16), 25, (1, 1, 1), direction=Vec2(1, 0), length=2000,
                      illumination_gain=0, reflection_radius=100),
    ])
    image = debug_pixels(ground, texture, mode=5)
    assert max(p[0] for p in image) > .02


@pytest.mark.parametrize("population", [1, 600])
@pytest.mark.parametrize("beam", [False, True])
def test_body_occludes_only_its_sources_reflection(ground_material, mocker, beam, population) -> None:
    ground, texture = ground_material
    uniform_deep_film(ground, texture)
    pool = CreaturePool()
    pool.entries[0] = CreatureState(active=True, hp=100, pos=Vec2(32, 26), size=35)
    body = BodyVolume(Vec2(32, 26), Vec2(7, 4), 24, 0)
    distant = [msgspec.structs.replace(body, pos=Vec2(4000, 4000))] * (population - 1)
    proxy = mocker.patch.object(ground_materials, "creature_body_volumes", side_effect=lambda c: [body, *distant] if c.active else [])
    source = MaterialLight(Vec2(32, 16), 150, (2, 1, .5), height=30,
                           direction=Vec2(1, 0), length=24 if beam else 0, illumination_gain=0)
    collector = mocker.patch.object(ground_materials, "collect_material_lights", return_value=[source])
    unblocked = debug_pixels(ground, texture, mode=5)
    blocked = debug_pixels(ground, texture, mode=5, creatures=pool)
    assert sum(p[0] for p in blocked) < sum(p[0] for p in unblocked) * .8
    assert all(b[0] <= a[0] for a, b in zip(unblocked, blocked, strict=True))
    assert all(math.isfinite(c) for p in blocked for c in p)
    assert {p[3] for p in blocked} == {1.}
    # A low body is below the actual source ray, not an arbitrary flattened shadow ray.
    low = msgspec.structs.replace(body, height=1)
    proxy.side_effect = lambda c: [low, *distant] if c.active else []
    cleared = debug_pixels(ground, texture, mode=5, creatures=pool)
    assert sum(p[0] for p in cleared) > sum(p[0] for p in blocked) * 1.2
    proxy.side_effect = lambda c: [body, *distant] if c.active else []
    # Ambient is unchanged; disabling dynamic shadows retains diffuse light.
    for sources in ([], [msgspec.structs.replace(source, illumination_gain=1, reflection_gain=0)]):
        collector.return_value = sources
        assert debug_pixels(ground, texture, mode=0, shadows=False) == debug_pixels(ground, texture, mode=0, creatures=pool, shadows=False)
    # Unobstructed second sources do not inherit the first source's shadow.
    other = MaterialLight(Vec2(4, 4), 100, (0, 1, 0), height=30, illumination_gain=0)
    collector.return_value = [other]
    green = debug_pixels(ground, texture, mode=5, creatures=pool)
    collector.return_value = [source, other]
    both = debug_pixels(ground, texture, mode=5, creatures=pool)
    assert [p[1] for p in both] == pytest.approx([a[1] + b[1] for a, b in zip(blocked, green, strict=True)], abs=.001)
    assert ground.reflection_occlusion.texture is not None
    ground.reset_materials()
    assert ground.reflection_occlusion.texture is None


def test_rounded_body_rotation_and_source_width_change_the_occlusion(ground_material, mocker) -> None:
    ground, texture = ground_material
    uniform_deep_film(ground, texture)
    pool = CreaturePool()
    pool.entries[0] = CreatureState(active=True, hp=100)
    body = BodyVolume(Vec2(32, 26), Vec2(10, 3), 24, 0)
    proxy = mocker.patch.object(ground_materials, "creature_body_volumes", side_effect=lambda c: [body] if c.active else [])
    source = MaterialLight(Vec2(32, 16), 150, (1, 1, 1), height=30,
                           direction=Vec2(1, 0), length=40, illumination_gain=0)
    collector = mocker.patch.object(ground_materials, "collect_material_lights", return_value=[source])
    horizontal = debug_pixels(ground, texture, mode=5, creatures=pool)
    distant = [msgspec.structs.replace(body, pos=Vec2(4000, 4000))] * 511
    proxy.side_effect = lambda c: [body, *distant] if c.active else []
    assert debug_pixels(ground, texture, mode=5, creatures=pool) == horizontal
    proxy.side_effect = lambda c: [msgspec.structs.replace(body, angle=math.pi/2)] if c.active else []
    vertical = debug_pixels(ground, texture, mode=5, creatures=pool)
    assert horizontal != vertical
    proxy.side_effect = lambda c: [body] if c.active else []
    ratios = []
    for width in (.5, 8):
        collector.return_value = [msgspec.structs.replace(source, source_width=width)]
        base = debug_pixels(ground, texture, mode=5)
        occluded = debug_pixels(ground, texture, mode=5, creatures=pool)
        ratios.append([b[0] / a[0] for a, b in zip(base, occluded, strict=True) if a[0] > .01])
    # A wider finite source creates more partially visible pixels at the boundary.
    assert sum(.05 < v < .95 for v in ratios[1]) > sum(.05 < v < .95 for v in ratios[0])



def test_living_sprite_proxy_reaches_material_scope_without_touching_classic(ground_material, mocker) -> None:
    ground, texture = ground_material
    uniform_deep_film(ground, texture)
    pool = CreaturePool()
    pool.entries[0] = CreatureState(active=True, hp=100, pos=Vec2(32, 26), size=50, heading=math.pi/2)
    mocker.patch.object(ground_materials, "collect_material_lights", return_value=[
        MaterialLight(Vec2(32, 16), 150, (1, 1, 1), height=30, direction=Vec2(1, 0), length=30, illumination_gain=0),
    ])
    classic = pixels(ground.render_target)
    clear = debug_pixels(ground, texture, mode=5)
    alive = debug_pixels(ground, texture, mode=5, creatures=pool)
    assert sum(p[0] for p in alive) < sum(p[0] for p in clear)
    pool.entries[0].hp = 0
    assert debug_pixels(ground, texture, mode=5, creatures=pool) == alive
    pool.entries[0].death_timer = 0
    assert debug_pixels(ground, texture, mode=5, creatures=pool) == clear
    assert pixels(ground.render_target) == classic


def test_spatial_cell_crossing_does_not_drop_a_soft_body(ground_material, mocker) -> None:
    ground, texture = ground_material
    uniform_deep_film(ground, texture)
    pool = CreaturePool()
    pool.entries[0] = CreatureState(active=True, hp=100)
    # The expanded body footprint crosses the x=0 cell edge. This also exercises
    # a ray pointing out of the arena toward a selected source outside it.
    body = BodyVolume(Vec2(0, 26), Vec2(7, 4), 24, .2)
    proxy = mocker.patch.object(ground_materials, "creature_body_volumes", side_effect=lambda c: [body] if c.active else [])
    mocker.patch.object(ground_materials, "collect_material_lights", return_value=[
        MaterialLight(Vec2(-1, 16), 150, (1, 1, 1), height=30, source_width=5, illumination_gain=0),
    ])
    base = debug_pixels(ground, texture, mode=5)
    images = []
    for offset in (-.01, .01):
        shifted = msgspec.structs.replace(body, pos=Vec2(offset, 26))
        proxy.side_effect = lambda c, b=shifted: [b] if c.active else []
        images.append(debug_pixels(ground, texture, mode=5, creatures=pool))
    energies = [sum(p[0] for p in im) for im in images]
    assert energies[0] == pytest.approx(energies[1], rel=.01)
    assert max(energies) < sum(p[0] for p in base) * .9


def test_dynamic_shadow_switch_does_not_disable_reflection_visibility(ground_material, mocker):
    ground, texture = ground_material
    uniform_deep_film(ground, texture)
    pool = CreaturePool()
    pool.entries[0] = CreatureState(active=True, hp=100, pos=Vec2(32, 26), size=35)
    body = BodyVolume(Vec2(32, 26), Vec2(7, 4), 24, 0)
    mocker.patch.object(ground_materials, "creature_body_volumes", side_effect=lambda c: [body] if c.active else [])
    source = MaterialLight(Vec2(32, 16), 150, (2, 1, .5), height=24, reflection_gain=0, broad_illumination=True)
    collector = mocker.patch.object(ground_materials, "collect_material_lights", return_value=[source])
    clear = debug_pixels(ground, texture, mode=0, creatures=pool, shadows=False)
    shadow = debug_pixels(ground, texture, mode=0, creatures=pool)
    assert sum(p[0] for p in shadow) < sum(p[0] for p in clear) * .95
    assert all(b[0] <= a[0] for a, b in zip(clear, shadow, strict=True))
    collector.return_value = [msgspec.structs.replace(source, illumination_gain=0, reflection_gain=1)]
    assert debug_pixels(ground, texture, mode=5, creatures=pool) == debug_pixels(ground, texture, mode=5, creatures=pool, shadows=False)
    collector.return_value = []
    debug_pixels(ground, texture, mode=0, creatures=pool)
    assert ground.reflection_occlusion.grid is None


def test_direct_shadows_are_per_source_and_coincident_zero_height_is_finite(ground_material, mocker):
    ground, texture = ground_material
    uniform_deep_film(ground, texture)
    pool = CreaturePool()
    pool.entries[0] = CreatureState(active=True, hp=100, pos=Vec2(32, 26), size=35)
    body = BodyVolume(Vec2(32, 26), Vec2(7, 4), 24, 0)
    mocker.patch.object(ground_materials, "creature_body_volumes", side_effect=lambda c: [body] if c.active else [])
    red_source = MaterialLight(Vec2(32, 16), 150, (2, 0, 0), height=24, reflection_gain=0)
    green_source = MaterialLight(Vec2(4, 4), 150, (0, 2, 0), height=24, reflection_gain=0)
    collector = mocker.patch.object(ground_materials, "collect_material_lights", return_value=[red_source])
    red = debug_pixels(ground, texture, mode=0, creatures=pool)
    collector.return_value = [green_source]
    green = debug_pixels(ground, texture, mode=0, creatures=pool)
    collector.return_value = [red_source, green_source]
    both = debug_pixels(ground, texture, mode=0, creatures=pool)
    assert [p[0] for p in both] == pytest.approx([p[0] for p in red], abs=.001)
    assert [p[1] for p in both] == pytest.approx([p[1] for p in green], abs=.001)
    collector.return_value = [msgspec.structs.replace(red_source, pos=Vec2(32.5, 31.5), height=0)]
    result = debug_pixels(ground, texture, mode=0, creatures=pool)
    assert all(math.isfinite(c) for p in result for c in p)


@pytest.mark.parametrize("broad", [False, True])
def test_weak_sources_keep_cosine_response_without_broad_grazing_fill(ground_material, mocker, broad):
    ground, texture = ground_material
    collector = mocker.patch.object(ground_materials, "collect_material_lights", return_value=[])
    base = debug_pixels(ground, texture, mode=0)
    center = 32 * 64 + 32
    increments = []
    for height in (12., 24.):
        collector.return_value = [MaterialLight(Vec2(32.5, 4.5), 100, (.7, 0, 0), height=height,
                                               reflection_gain=0, broad_illumination=broad)]
        lit = debug_pixels(ground, texture, mode=0)
        increments.append(lit[center][0] ** 2.2 - base[center][0] ** 2.2)
    ndls = [height / math.hypot(height, 27.) for height in (12., 24.)]
    expected = [( .22 + .78 * ndl) if broad else .22 * ndl for ndl in ndls]
    assert increments[0] / increments[1] == pytest.approx(expected[0] / expected[1], rel=.025)


def test_negligible_ground_diffuse_skip_has_bounded_linear_error(ground_material, mocker):
    from crimson.render.rtx.material_shaders import GROUND_FRAGMENT

    ground, texture = ground_material
    uniform_deep_film(ground, texture)
    pool = CreaturePool()
    pool.entries[0] = CreatureState(active=True, hp=100, pos=Vec2(32, 26), size=35)
    body = BodyVolume(Vec2(32, 26), Vec2(7, 4), 24, 0)
    mocker.patch.object(ground_materials, "creature_body_volumes", side_effect=lambda c: [body] if c.active else [])
    source = MaterialLight(Vec2(32, 16), 150, (.0001, .0001, .0001), height=24,
                           reflection_gain=0, broad_illumination=True)
    mocker.patch.object(ground_materials, "collect_material_lights", return_value=[source])
    pixel_format = rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32
    approximate = debug_pixels(ground, texture, mode=0, creatures=pool, pixel_format=pixel_format)
    original = ground.material_shader
    reference = ground_materials._shader(GROUND_FRAGMENT.replace(
        "max(direct.r, max(direct.g, direct.b)) > .00001", "max(direct.r, max(direct.g, direct.b)) > 0."))
    try:
        ground.material_shader = reference
        exact = debug_pixels(ground, texture, mode=0, creatures=pool, pixel_format=pixel_format)
    finally:
        ground.material_shader = original
        rl.unload_shader(reference)
    errors = [a[c] ** 2.2 - b[c] ** 2.2 for a, b in zip(approximate, exact, strict=True) for c in range(3)]
    assert max(errors) > 0
    assert min(errors) >= -1e-7
    assert max(errors) <= 1.01e-5


def test_ring_reflection_tracks_annular_footprint_instead_of_center(ground_material, mocker):
    ground, texture = ground_material
    uniform_deep_film(ground, texture)
    collector = mocker.patch.object(ground_materials, "collect_material_lights")
    ring = MaterialLight(Vec2(32, 16), 80, (1, .5, .2), height=18, ring_radius=18,
                         source_width=2, illumination_gain=0)
    collector.return_value = [ring]
    reflected = debug_pixels(ground, texture, mode=5)
    collector.return_value = [msgspec.structs.replace(ring, ring_radius=0)]
    point = debug_pixels(ground, texture, mode=5)
    assert max(p[0] for p in reflected) > .05
    assert sum(abs(a[0] - b[0]) for a, b in zip(reflected, point, strict=True)) > 1
    assert all(math.isfinite(c) for p in reflected for c in p)


def test_direct_debug_maps_show_clean_ground_lighting_and_weighted_visibility(ground_material, mocker):
    ground, texture = ground_material
    pool = CreaturePool()
    pool.entries[0] = CreatureState(active=True, hp=100, pos=Vec2(32, 26), size=35)
    body = BodyVolume(Vec2(32, 26), Vec2(7, 4), 24, 0)
    mocker.patch.object(ground_materials, "creature_body_volumes", side_effect=lambda c: [body] if c.active else [])
    collector = mocker.patch.object(ground_materials, "collect_material_lights", return_value=[
        MaterialLight(Vec2(32, 16), 150, (2, 1, .5), height=24, reflection_gain=0, broad_illumination=True),
    ])
    clear = debug_pixels(ground, texture, mode=7, creatures=pool)
    shadow = debug_pixels(ground, texture, mode=6, creatures=pool)
    visibility = debug_pixels(ground, texture, mode=8, creatures=pool)
    assert max(p[0] for p in clear) > .05  # No blood/corpse coverage is needed for direct lighting.
    assert sum(p[0] for p in shadow) < sum(p[0] for p in clear) * .95
    assert min(p[0] for p in visibility) < .5
    assert max(p[0] for p in visibility) > .99
    weights = (.2126, .7152, .0722)
    for a, b, v in zip(clear, shadow, visibility, strict=True):
        total = sum(a[i] * weights[i] for i in range(3))
        if total > 1e-5:
            expected = sum(b[i] * weights[i] for i in range(3)) / total
            assert v[0] == pytest.approx(expected, abs=.003)
    collector.return_value = []
    assert all(p[:3] == pytest.approx((.12, .16, .22), abs=.001) for p in debug_pixels(ground, texture, mode=8))


def test_live_debug_maps_preserve_normals_and_compress_hdr_contributions(ground_material, mocker):
    ground, texture = ground_material
    mocker.patch.object(ground_materials, "collect_material_lights", return_value=[
        MaterialLight(Vec2(32, 16), 150, (200, 100, 50), height=24, reflection_gain=0, broad_illumination=True),
    ])
    assert debug_pixels(ground, texture, mode=1, live=True) == debug_pixels(ground, texture, mode=1)
    raw = debug_pixels(ground, texture, mode=6)
    displayed = debug_pixels(ground, texture, mode=6, live=True)
    assert max(p[0] for p in raw) > 1
    assert all(0 <= c <= 1 for p in displayed for c in p)
    for a, b in zip(raw, displayed, strict=True):
        assert b[:3] == pytest.approx(tuple((c / (1 + c)) ** (1 / 2.2) for c in a[:3]), abs=.001)


def test_no_direct_is_a_matched_beauty_comparison(ground_material, mocker):
    ground, texture = ground_material
    uniform_deep_film(ground, texture)
    collector = mocker.patch.object(ground_materials, "collect_material_lights", return_value=[
        MaterialLight(Vec2(32, 16), 150, (2, 1, .5), height=24, broad_illumination=True),
    ])
    without_direct = debug_pixels(ground, texture, mode=14, live=True)
    collector.return_value = [msgspec.structs.replace(collector.return_value[0], illumination_gain=0)]
    # Exactly the ordinary beauty pass with direct gain off; reflections remain present.
    assert debug_pixels(ground, texture, mode=0) == without_direct


@pytest.mark.parametrize("ring_radius", [0., 18.])
def test_reflection_tail_uniform_only_tapers_segments_not_annuli(ground_material, mocker, ring_radius):
    ground, texture = ground_material
    uniform_deep_film(ground, texture)
    collector = mocker.patch.object(ground_materials, "collect_material_lights")
    source = MaterialLight(Vec2(32, 16), 80, (1, .5, .2), height=18, ring_radius=ring_radius,
                           direction=Vec2(1, 0), length=28, source_width=2, illumination_gain=0)
    collector.return_value = [msgspec.structs.replace(source, reflection_tail=0)]
    tapered = debug_pixels(ground, texture, mode=5)
    collector.return_value = [msgspec.structs.replace(source, reflection_tail=1)]
    uniform = debug_pixels(ground, texture, mode=5)
    if ring_radius:
        assert tapered == uniform
    else:
        assert sum(b[0] - a[0] for a, b in zip(tapered, uniform, strict=True)) > 1


def test_visible_death_shadow_collapses_without_an_instant_hp_cutoff(ground_material, mocker):
    ground, texture = ground_material
    pool = CreaturePool()
    creature = CreatureState(active=True, hp=100, pos=Vec2(32, 26), size=44,
                             type_id=CreatureTypeId.SPIDER_SP1, heading=math.pi / 2)
    pool.entries[0] = creature
    mocker.patch.object(ground_materials, "collect_material_lights", return_value=[
        MaterialLight(Vec2(32, 10), 150, (2, 1, .5), height=18, reflection_gain=0, broad_illumination=True),
    ])
    clear = debug_pixels(ground, texture, mode=7, creatures=pool)
    living = debug_pixels(ground, texture, mode=6, creatures=pool)
    creature.hp = 0
    killed = debug_pixels(ground, texture, mode=6, creatures=pool)
    assert killed == living
    blocked = sum(a[0] - b[0] for a, b in zip(clear, killed, strict=True))
    assert blocked > .1
    creature.death_timer = 2
    low = debug_pixels(ground, texture, mode=6, creatures=pool)
    remaining = sum(a[0] - b[0] for a, b in zip(clear, low, strict=True))
    assert 0 <= remaining < blocked * .2
    creature.death_timer = 0
    assert debug_pixels(ground, texture, mode=6, creatures=pool) == clear


@pytest.mark.parametrize("ion,gain_name,gain", [(True, "ION_DIRECT_GAIN", 4.), (False, "FIRE_DIRECT_GAIN", 3.)])
def test_default_beam_material_scope_upload_and_source_transitions_real_pixels(ground_material, mocker, monkeypatch, ion, gain_name, gain) -> None:
    ground, texture = ground_material
    # A masked source before the beam catches an incorrect vec4 count/row offset.
    reflection_only = MaterialLight(Vec2(32, 20), 150, (1, 1, 1), illumination_gain=0)
    beam = MaterialLight(
        Vec2(32, 20), 150, (.5, .8, 1.4), height=24, direction=Vec2(1, 0), length=48,
        broad_illumination=True, beam_profile=(35.2, 6.82, 1.05), beam_ion=ion,
    )
    collector = mocker.patch.object(ground_materials, "collect_material_lights", return_value=[reflection_only, beam])
    upload = mocker.spy(rl, "set_shader_value_v")

    def render():
        return debug_pixels(ground, texture, mode=int(RtxDebugView.DIRECT_UNSHADOWED))

    # Capture a non-beam frame before beam uniforms have ever been uploaded.
    nonbeam = msgspec.structs.replace(beam, beam_profile=None, beam_ion=False)
    collector.return_value = [nonbeam]
    baseline = render()
    collector.return_value = [reflection_only, beam]
    boosted = render()  # Accepted lighting is active without a separate control.
    monkeypatch.setattr(ground_materials, gain_name, 1.)
    one = render()
    assert max(pixel[2] for pixel in one) > .001
    # Exercise material_scope's real array binding and CFFI pointer conversion.
    for normal, bright in zip(one, boosted, strict=True):
        assert bright[:3] == pytest.approx(tuple(channel * gain for channel in normal[:3]), rel=.002, abs=.001)
    calls = [call for call in upload.call_args_list if call.args[1] == ground.material_locations["u_beam_shape[0]"]]
    assert len(calls) == 2
    assert all(call.args[4] == 2 and rl.ffi.typeof(call.args[2]).cname == "void *" for call in calls)
    monkeypatch.setattr(ground_materials, gain_name, gain)
    collector.return_value = [nonbeam]
    assert render() == baseline  # Stale beam shapes must not affect a later non-beam frame.
    collector.return_value = [reflection_only, beam]
    assert render() == boosted
    collector.return_value = []
    assert all(pixel[:3] == (0., 0., 0.) for pixel in render())


def test_ion_arcs_add_ground_light_and_wet_reflections(ground_material, mocker) -> None:
    from crimson.render.rtx.material_lights import ion_arc_sources
    from tests.render.test_ion_arc_lights import scene

    ground, texture = ground_material
    uniform_fresh_film(ground, texture)
    frame, shot = scene()
    shot.pos = Vec2(16, 20)
    frame.creatures.entries[1].pos = Vec2(48, 20)
    collector = mocker.patch.object(ground_materials, "collect_material_lights", return_value=[])
    baseline = {mode: debug_pixels(ground, texture, mode=mode) for mode in (5, 6)}
    collector.return_value = ion_arc_sources(frame, shot)
    for mode in (5, 6):
        lit = debug_pixels(ground, texture, mode=mode)
        assert max(after[2] - before[2] for before, after in zip(baseline[mode], lit, strict=True)) > .001, mode
    shot.life_timer = 0
    collector.return_value = ion_arc_sources(frame, shot)
    assert debug_pixels(ground, texture, mode=5) == baseline[5]
    assert debug_pixels(ground, texture, mode=6) == baseline[6]


@pytest.mark.parametrize("ion", [False, True])
def test_beams_add_light_without_dimming_the_ambient(ground_material, mocker, ion):
    ground, texture = ground_material
    collector = mocker.patch.object(ground_materials, "collect_material_lights", return_value=[])

    def ambient():
        return debug_pixels(ground, texture, mode=int(RtxDebugView.AMBIENT))

    baseline = ambient()
    collector.return_value = [MaterialLight(
        Vec2(32, 32), 150, (1.65, .8, .2), height=24, direction=Vec2(1, 0), length=48,
        broad_illumination=True, beam_profile=(12.8, 2.48, 1.35), beam_ion=ion,
    )] * 8
    assert ambient() == baseline


@pytest.mark.parametrize("height,width,length,ring", [
    (0., 3., 0., 0.), (11.9, 3., 0., 0.), (12., 3., 0., 0.), (30., 3., 0., 0.),
    (30., .05, 0., 0.), (30., .1, 0., 0.), (30., 3., 24., 0.), (30., 3., 0., 16.),
])
@pytest.mark.parametrize("shadows", [False, True])
def test_reflection_visibility_is_independent_of_diffuse_trace(
    ground_material, mocker, height, width, length, ring, shadows,
):
    ground, texture = ground_material
    uniform_deep_film(ground, texture)
    pool = CreaturePool()
    pool.entries[0] = CreatureState(active=True, hp=100, pos=Vec2(32, 26), size=35)
    body = BodyVolume(Vec2(32, 26), Vec2(7, 4), 24, 0)
    mocker.patch.object(ground_materials, "creature_body_volumes", side_effect=lambda c: [body] if c.active else [])
    source = MaterialLight(
        Vec2(32, 16), 150, (2, 1, .5), height=height, source_width=width,
        direction=Vec2(1, 0), length=length, ring_radius=ring, illumination_gain=0,
    )
    collect = mocker.patch.object(ground_materials, "collect_material_lights", return_value=[source])
    reference = debug_pixels(ground, texture, mode=5, creatures=pool, shadows=shadows)
    assert max(p[0] for p in reference) > 0
    # Diffuse disabled is an independent reference: it cannot populate a cached trace.
    # Include a negligible diffuse source, for which tracing is also skipped.
    for gain in (1e-10, 1.):
        collect.return_value = [msgspec.structs.replace(source, illumination_gain=gain)]
        assert debug_pixels(ground, texture, mode=5, creatures=pool, shadows=shadows) == reference


def test_bulk_light_upload_matches_scalar_upload_after_source_count_changes(ground_material, mocker):
    ground, texture = ground_material
    uniform_deep_film(ground, texture)
    sources = [MaterialLight(
        Vec2(10 + i, 8 + i % 7), 50 + i, (.1 + i * .02, .3, .5), height=12 + i,
        source_width=.2 + i * .1, reflection_tail=.1 + i * .01,
        direction=Vec2(1, 0), length=10 if i % 2 else 0,
        reflection_gain=.3, illumination_gain=.5,
    ) for i in range(32)]
    collect = mocker.patch.object(ground_materials, "collect_material_lights")
    bulk = ground._material_array

    def scalar(name, values, *, components):
        for i in range(len(values) // components):
            _uniform(ground.material_shader, name.replace("[0]", f"[{i}]"), values[i*components:(i+1)*components])

    for count in (32, 1, 0, 17):
        collect.return_value = sources[:count]
        with patch.object(MaterialGroundRenderer, "_material_array", side_effect=scalar):
            reference = debug_pixels(ground, texture, mode=0)
        assert ground._material_array == bulk
        assert debug_pixels(ground, texture, mode=0) == reference
