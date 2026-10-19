from __future__ import annotations

import struct
from pathlib import Path
from typing import Any, cast

import msgspec
import pytest

from crimson.creatures.runtime import CreaturePool
from crimson.effects import FxQueueEntry, FxQueueRotatedEntry
from crimson.render.frame import RenderFrame
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
    assert first[1] == pytest.approx(1200.25)
    assert 0.3 < first[2] < 0.7
    # Blood leaves the entire substrate height field untouched, including its boundaries.
    assert {p[3] for p in pixels(ground.surface)} == {dry[3]}
    assert pixels(ground.coverage)[center][:3] == pytest.approx((1, 0, 0))
    ground.material_batches.append(blood(1202.5))
    ground.bake_materials(texture, texture)
    second = pixels(ground.surface)[center]
    assert second[2] > first[2]
    assert second[1] == pytest.approx(1202.5)
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
    assert pixels(ground.surface)[center][1] == 1300
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
            _uniform(sh, "u_time_s", [time])
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
    mocker.patch(
        "crimson.render.rtx.materials.collect_material_lights",
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
    ground.bake_materials(texture, texture)
    assert pixels(ground.substrate.render_target) == before
    surface, coverage = pixels(ground.surface), pixels(ground.coverage)
    history = list(ground.material_batches)
    ground.reset_materials()
    ground.material_batches = history
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
    mocker.patch(
        "crimson.render.rtx.materials.collect_material_lights",
        return_value=[MaterialLight(Vec2(32, 32), 150, (4, 4, 4), height=30)],
    )
    target = load_float_render_texture(67, 67)  # nonintegral sampling exercises filtering at empty edges
    renders = []
    try:
        for time in (0.0, 36000.25):
            ground.reset_materials()
            batch = blood(time)
            entry = msgspec.structs.replace(batch.decals[0], effect_id=effect_id, color=RGBA(1, 0, 0, 0.1))
            ground.material_batches = [msgspec.structs.replace(batch, decals=(entry,))]
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
    assert after[1] == before[1]
    assert pixels(ground.coverage)[center][0] < 0.6
