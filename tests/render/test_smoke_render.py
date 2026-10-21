from __future__ import annotations

import math

import msgspec
import numpy as np
import pytest

from crimson.effects import EffectEntry
from crimson.effects_atlas import EffectId
from crimson.perks import PerkId
from crimson.render.rtx.debug import RtxDebugView
from crimson.render.rtx.material_lights import MaterialLight
from crimson.render.rtx.mode import RtxRenderMode
from crimson.render.rtx.smoke import SmokeRenderer
from crimson.render.rtx.smoke_simulation import SmokeField
from crimson.render.world import draw as world_draw
from crimson.render.world import effects
from crimson.render.world.viewport import ViewTransform
from crimson.sim.sessions import DeterministicSession
from crimson.sim.state_types import PlayerState
from crimson.world.render_resources import RenderResources
from grim.color import RGBA
from grim.config import default_crimson_cfg
from grim.edr import load_float_render_texture
from grim.geom import Vec2
from grim.rand import Crand
from grim.raylib_api import rl
from grim.texture_mode import texture_mode
from tests.render.test_smoke_simulation import emission
from tests.support.creature_draw_capture import render_ctx_for_creatures
from tests.support.world_runtime import WorldRuntimeHost


def test_runtime_toggle_reset_restore_and_smoke_setting(tmp_path, headless_resources):
    config = default_crimson_cfg()
    runtime = WorldRuntimeHost(assets_dir=tmp_path, config=config, rtx_mode=RtxRenderMode.RTX)
    runtime.render_resources.resources = headless_resources
    resources = runtime.render_resources
    resources.set_simulated_smoke(True)
    resources.consume_smoke_batch((emission(),), dt_sim=0.)
    assert resources.smoke.simulation.fields
    frame = runtime.build_render_frame()
    assert frame.smoke is resources.smoke
    runtime.rtx_mode = RtxRenderMode.CLASSIC
    assert not resources.smoke.simulation.fields
    assert runtime.build_render_frame().smoke is None
    runtime.rtx_mode = RtxRenderMode.RTX
    assert not resources.smoke.simulation.fields
    resources.consume_smoke_batch((emission(),), dt_sim=0.)
    config.display.smoke_enabled = False
    assert runtime.build_render_frame().smoke is None
    assert not resources.smoke.simulation.fields
    config.display.smoke_enabled = True
    resources.consume_smoke_batch((emission(delay_seconds=.5),), dt_sim=0.)
    assert resources.smoke.simulation.pending
    runtime.start_session(DeterministicSession.start(runtime.world, perk_progression_enabled=False))
    assert not resources.smoke.simulation.pending
    resources.consume_smoke_batch((emission(),), dt_sim=0.)
    runtime.reset()
    assert not resources.smoke.simulation.fields


def test_rtx_suppresses_all_native_smoke_even_unclaimed_and_reused_slots(headless_window, headless_resources):
    ctx = render_ctx_for_creatures(headless_resources, [])
    smoke = SmokeRenderer()
    ctx = msgspec.structs.replace(ctx, frame=msgspec.structs.replace(ctx.frame, rtx_mode=RtxRenderMode.RTX, smoke=smoke))
    pool = ctx.frame.state.sprite_effects
    pool.spawn(pos=Vec2(50, 50), vel=Vec2(), scale=14, color=RGBA(1, 1, 1, .25), rng=Crand(1))
    with pool.capture_emissions() as captured:
        claimed = pool.spawn(pos=Vec2(52, 50), vel=Vec2(), scale=14, color=RGBA(1, 1, 1, .25), rng=Crand(2))
    smoke.consume(tuple(captured), dt_sim=0.)
    smoke.prepared = True
    effects.draw_sprite_effect_pool(ctx, camera=Vec2(), view_scale=Vec2(1, 1))
    assert headless_window.draw_texture_pro.call_count == 0
    pool.entries[claimed].active = False
    pool.spawn(pos=Vec2(900, 900), vel=Vec2(), scale=14, color=RGBA(1, 1, 1, .25), rng=Crand(3))
    headless_window.draw_texture_pro.reset_mock()
    effects.draw_sprite_effect_pool(ctx, camera=Vec2(), view_scale=Vec2(1, 1))
    assert headless_window.draw_texture_pro.call_count == 0
    classic = msgspec.structs.replace(ctx, frame=msgspec.structs.replace(ctx.frame, rtx_mode=RtxRenderMode.CLASSIC))
    effects.draw_sprite_effect_pool(classic, camera=Vec2(), view_scale=Vec2(1, 1))
    assert headless_window.draw_texture_pro.call_count == 2


def test_map_view_skips_smoke_and_draws_do_not_advance_it(mocker, headless_window, headless_resources):
    ctx = render_ctx_for_creatures(headless_resources, [])
    smoke = SmokeRenderer()
    smoke.consume((emission(),), dt_sim=0.)
    ctx = msgspec.structs.replace(ctx, frame=msgspec.structs.replace(
        ctx.frame, rtx_mode=RtxRenderMode.RTX, rtx_debug=RtxDebugView.ALBEDO, smoke=smoke,
    ))
    prepare = mocker.patch.object(smoke, "prepare")
    draw = mocker.patch.object(smoke, "draw")
    mocker.patch.object(world_draw, "draw_background")
    world_draw.draw_world(ctx)
    world_draw.draw_world(ctx)
    prepare.assert_not_called()
    draw.assert_not_called()
    assert smoke.simulation.fields[0].idle_seconds == 0.


def test_close_releases_resources_once(mocker, tmp_path):
    smoke = SmokeRenderer()
    shader = rl.ffi.new("Shader *")[0]
    shader.id = 42
    smoke.shader = shader
    texture = rl.Texture(12, 144, 144, 1, rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32)
    smoke.textures[0] = texture
    unload_shader = mocker.patch.object(rl, "unload_shader")
    unload_texture = mocker.patch.object(rl, "unload_texture")
    owner = RenderResources(tmp_path, smoke=smoke)
    owner.close()
    owner.close()
    unload_shader.assert_called_once_with(shader)
    unload_texture.assert_called_once_with(texture)


@pytest.fixture
def smoke_pixels(raylib_context, headless_resources):
    ctx = render_ctx_for_creatures(headless_resources, [])
    player = PlayerState(index=0, pos=Vec2(0, 64), aim_heading=math.pi / 2)
    smoke = SmokeRenderer()
    field = SmokeField(Vec2(-80, -80), 1)
    field.density.fill(.3)
    field.temperature.fill(.5)
    smoke.simulation.fields[0] = field
    ctx = msgspec.structs.replace(
        ctx, frame=msgspec.structs.replace(ctx.frame, rtx_mode=RtxRenderMode.RTX, smoke=smoke, players=[player]),
        view=ViewTransform(camera=Vec2(), view_scale=Vec2(1, 1), screen_size=Vec2(128, 128), out_size=Vec2(128, 128)),
    )
    target = load_float_render_texture(128, 128)

    def render(*, lights=(), sight=False, density=.3, grow=False):
        field.density.fill(density)
        if grow:
            field.include(Vec2(350, 64), 200.)
        field.version += 1
        ctx.frame.state.perks[PerkId.SHARPSHOOTER] = int(sight)
        smoke.prepare(ctx.frame, lights)
        with texture_mode(target):
            rl.clear_background(rl.BLANK)
            smoke.draw(ctx, alpha=1.)
        image = rl.load_image_from_texture(target.texture)
        try:
            rl.image_format(image, rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32)
            return np.frombuffer(rl.ffi.buffer(image.data, 128 * 128 * 16), dtype=np.float32).reshape(128, 128, 4)[::-1].copy()
        finally:
            rl.unload_image(image)

    try:
        yield render
    finally:
        smoke.close()
        rl.unload_render_texture(target)


def test_native_shader_light_and_sight_scatter_only_in_density(smoke_pixels):
    ambient = smoke_pixels()
    warm = smoke_pixels(lights=[MaterialLight(Vec2(64, 64), 160, (1.4, .68, .2), height=30)])
    dim = smoke_pixels(lights=[MaterialLight(Vec2(64, 64), 160, (1.4, .68, .2), height=30, illumination_gain=.25)])
    sight = smoke_pixels(sight=True)
    assert np.isfinite(warm).all()
    assert np.mean(warm[:, :, 0] - ambient[:, :, 0]) > .01
    np.testing.assert_allclose(dim - ambient, (warm - ambient) * .25, atol=.0001)
    assert np.mean(sight[58:70, :, 0] - ambient[58:70, :, 0]) > .01
    assert np.max(np.abs(sight[:30] - ambient[:30])) < .001
    assert np.max(np.abs(smoke_pixels(sight=True, density=0.))) == 0.


def test_native_shader_preserves_faint_extinction_without_sprite_alpha_test(smoke_pixels):
    faint = smoke_pixels(density=.008)
    assert 0. < float(faint[:, :, 0].mean()) < .015


def test_smoke_light_budget_culls_remote_sources_and_prioritizes_exhaust():
    smoke = SmokeRenderer()
    smoke.simulation.fields[0] = SmokeField(Vec2(0, 0), 0)
    far = [MaterialLight(Vec2(900, 900), 100, (1., .5, .1)) for _ in range(20)]
    nearby = [MaterialLight(Vec2(100, 100), 100, (.2, .2, .2)) for _ in range(20)]
    exhaust = MaterialLight(Vec2(100, 100), 100, (.9, .47, .1), smoke_gain=6.)
    selected = smoke.select_lights([*far, *nearby, exhaust])
    assert len(selected) == 16 and selected[0] is exhaust
    assert not any(light in far for light in selected)


def test_native_texture_resize_preserves_world_space_density(smoke_pixels):
    before = smoke_pixels()
    after = smoke_pixels(grow=True)
    np.testing.assert_allclose(after, before, atol=.00001)


def test_rtx_suppresses_general_explosion_puffs_but_keeps_other_effects(headless_window, headless_resources):
    ctx = render_ctx_for_creatures(headless_resources, [])
    pool = ctx.frame.state.effects
    puff = EffectEntry(pos=Vec2(50, 50), effect_id=EffectId.EXPLOSION_PUFF, flags=0x40,
                       scale=1., half_width=20., half_height=20., color=RGBA(1, 1, 1, 1))
    pool.entries[0] = puff
    pool.entries[1] = msgspec.structs.replace(puff, effect_id=EffectId.RING)
    rtx = msgspec.structs.replace(ctx, frame=msgspec.structs.replace(ctx.frame, rtx_mode=RtxRenderMode.RTX, smoke=SmokeRenderer()))
    effects.draw_effect_pool(rtx, camera=Vec2(), view_scale=Vec2(1, 1))
    assert headless_window.draw_texture_pro.call_count == 1
    headless_window.draw_texture_pro.reset_mock()
    classic = msgspec.structs.replace(ctx, frame=msgspec.structs.replace(ctx.frame, rtx_mode=RtxRenderMode.CLASSIC))
    effects.draw_effect_pool(classic, camera=Vec2(), view_scale=Vec2(1, 1))
    assert headless_window.draw_texture_pro.call_count == 2


def test_default_rtx_skips_solver_and_toggle_clears_delayed_deposits(tmp_path, mocker, headless_resources):
    runtime = WorldRuntimeHost(assets_dir=tmp_path, rtx_mode=RtxRenderMode.RTX)
    resources = runtime.render_resources
    resources.resources = headless_resources
    consume = mocker.spy(resources.smoke, "consume")
    assert not resources.simulated_smoke_enabled
    resources.consume_smoke_batch((emission(),), dt_sim=1 / 60)
    consume.assert_not_called()
    assert runtime.build_render_frame().smoke is None
    resources.set_simulated_smoke(True)
    resources.consume_smoke_batch((emission(), emission(delay_seconds=.5)), dt_sim=0.)
    assert resources.smoke.simulation.fields and resources.smoke.simulation.pending
    resources.set_simulated_smoke(False)
    assert not resources.smoke.simulation.fields and not resources.smoke.simulation.pending
    assert runtime.build_render_frame().smoke is None
    resources.set_simulated_smoke(True)
    assert not resources.smoke.simulation.fields and not resources.smoke.simulation.pending


def test_default_rtx_restores_both_native_smoke_pools(headless_window, headless_resources):
    ctx = render_ctx_for_creatures(headless_resources, [])
    ctx = msgspec.structs.replace(ctx, frame=msgspec.structs.replace(ctx.frame, rtx_mode=RtxRenderMode.RTX))
    ctx.frame.state.sprite_effects.spawn(pos=Vec2(50, 50), vel=Vec2(), scale=14,
                                       color=RGBA(1, 1, 1, .25), rng=Crand(1))
    ctx.frame.state.effects.entries[0] = EffectEntry(
        pos=Vec2(50, 50), effect_id=EffectId.EXPLOSION_PUFF, flags=0x40,
        scale=1., half_width=20., half_height=20., color=RGBA(1, 1, 1, 1),
    )
    effects.draw_sprite_effect_pool(ctx, camera=Vec2(), view_scale=Vec2(1, 1))
    effects.draw_effect_pool(ctx, camera=Vec2(), view_scale=Vec2(1, 1))
    assert headless_window.draw_texture_pro.call_count == 2
