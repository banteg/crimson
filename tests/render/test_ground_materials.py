from __future__ import annotations

import math
import struct
from pathlib import Path
from typing import Any, cast

import msgspec
import pytest

from crimson.creatures.runtime import CreaturePool
from crimson.effects import FxQueueEntry, FxQueueRotatedEntry
from crimson.render.frame import RenderFrame
from crimson.render.rtx import materials as ground_materials
from crimson.render.rtx.material_lights import MaterialLight
from crimson.render.rtx.materials import MaterialGroundRenderer, _integer, _uniform
from crimson.render.rtx.mode import RtxRenderMode
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
        _uniform(sh, "u_spec_pos[0]", [32, 32, 150, 30])
        _uniform(sh, "u_spec_color[0]", [4, 4, 4, 0])
        _uniform(sh, "u_spec_dir[0]", [0, 0, 0, 0])
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
        return_value=[MaterialLight(Vec2(32, 32), 150, (4, 4, 4), height=30)],
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
        return_value=[MaterialLight(Vec2(32, 32), 150, (4, 4, 4), height=30)],
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


def debug_pixels(ground, texture, *, mode: int, time: float = 0) -> list[tuple[float, float, float, float]]:
    class Textures:
        def texture(self, _texture_id):
            return texture

    frame = RenderFrame(
        config=None, camera=Vec2(), ground=ground, state=GameplayState(), players=[], creatures=CreaturePool(),
        resources=cast(Any, Textures()), elapsed_ms=time * 1000, bonus_anim_phase=0, rtx_mode=RtxRenderMode.RTX,
    )
    target = load_float_render_texture(64, 64)
    try:
        with texture_mode(target), ground.material_scope(frame, debug=mode):
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
    assert all(p[:3] == pytest.approx((.5, .5, 1.)) for p in thin)
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
        collector.return_value = [MaterialLight(Vec2(32, 32), 150, (intensity, intensity, intensity), height=30)]
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
        MaterialLight(Vec2(32, 32), 150, (4, 4, 4), height=30),
    ])
    icy = debug_pixels(ground, texture, mode=0)
    # Remove only ice coverage: substrate color, relief, specularity and lights stay identical.
    with texture_mode(ground.coverage):
        rl.rl_color_mask(False, False, False, True)
        try:
            rl.clear_background(rl.BLANK)
        finally:
            rl.rl_color_mask(True, True, True, True)
    dry = debug_pixels(ground, texture, mode=0)
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
        ice = msgspec.structs.replace(blood(0).decals[0], effect_id=8, color=RGBA(1, 1, 1, .35))
        ground.material_batches.append(TerrainFxBatch(decals=(ice,)))
        ground.bake_materials(icy_texture, texture)
        blue = debug_pixels(ground, texture, mode=0)[center]
        assert blue[2] > blue[0] + .04
        ground.material_batches.extend([blood(1)] * 8)
        red = debug_pixels(ground, texture, mode=0, time=1)[center]
        assert red[0] > red[2]
        assert red[2] < blue[2] * .6
        n = ground.coverage.texture.width
        assert pixels(ground.coverage)[n // 2 * n + n // 2][3] == 0
    finally:
        rl.unload_texture(icy_texture)
