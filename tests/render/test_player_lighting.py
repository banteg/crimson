from __future__ import annotations

import math
import struct
from contextlib import contextmanager, nullcontext

import msgspec
import pytest

from crimson.render.rtx.creature_lighting import CreatureLighting
from crimson.render.rtx.material_lights import MAX_MATERIAL_LIGHTS, MaterialLight
from crimson.render.rtx.mode import RtxRenderMode
from crimson.render.rtx.player_lighting import PlayerLighting
from crimson.render.world import draw as world_draw
from crimson.render.world.context import WorldRenderCtx
from crimson.render.world.trooper import draw_player_trooper_sprite
from crimson.sim.state_types import PlayerState
from crimson.world.render_resources import RenderResources
from grim.assets import TextureId
from grim.edr import load_float_render_texture
from grim.geom import Vec2
from grim.raylib_api import rl, rl_rectangle, rl_vector2
from grim.shaders import AlphaTestShader
from grim.texture_mode import texture_mode
from tests.support.creature_draw_capture import render_ctx_for_creatures


@pytest.fixture
def player_sprite(raylib_context):
    image = rl.gen_image_color(256, 256, rl.BLANK)
    texture = rl.load_texture_from_image(image)
    rl.unload_image(image)
    target = load_float_render_texture(128, 128)
    lighting = PlayerLighting()
    alpha = AlphaTestShader()

    def render(lights, *, use_shader=True, rotation=0., scale=1., camera=Vec2(), neighbor=False,
               degenerate_uv=False, tint=rl.WHITE):
        image = rl.gen_image_color(256, 256, rl.BLANK)
        rl.image_draw_circle(image, 16, 16, 10, rl.Color(90, 90, 95, 255))
        rl.image_draw_rectangle(image, 24, 15, 8, 3, rl.Color(90, 90, 95, 255))
        # Painted ramp exercises relief as well as the dome; alpha 3 must discard.
        for y in range(10, 23):
            for x in range(10, 23):
                value = 50 + (x - 10) * 8 + (y - 10) * 3
                rl.image_draw_pixel(image, x, y, rl.Color(value, value, value, 255))
        rl.image_draw_pixel(image, 0, 0, rl.Color(255, 255, 255, 3))
        if neighbor:
            rl.image_draw_rectangle(image, 32, 0, 32, 32, rl.RED)
        rl.update_texture(texture, image.data)
        rl.unload_image(image)
        lighting.prepare(lights, camera=camera, view_scale=Vec2(scale, scale))
        with texture_mode(target, linear=True):
            rl.clear_background(rl.BLANK)
            with alpha.scope():
                def draw():
                    pos = (Vec2(64, 64) + camera) * scale
                    src = rl_rectangle(20, 16, 0, 0) if degenerate_uv else rl_rectangle(0, 0, 32, 32)
                    rl.draw_texture_pro(texture, src, rl_rectangle(pos.x, pos.y, 32*scale, 32*scale),
                                        rl_vector2(16*scale, 16*scale), rotation, tint)
                if use_shader:
                    with lighting.scope(restore_shader=alpha.shader):
                        draw()
                else:
                    draw()
        image = rl.load_image_from_texture(target.texture)
        try:
            rl.image_format(image, rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32)
            return list(struct.iter_unpack('ffff', bytes(rl.ffi.buffer(image.data, 128*128*16))))
        finally:
            rl.unload_image(image)

    try:
        yield render, lighting
    finally:
        lighting.close()
        alpha.close()
        rl.unload_texture(texture)
        rl.unload_render_texture(target)


def test_no_light_and_reflection_only_sources_preserve_native_pixels(player_sprite):
    render, lighting = player_sprite
    base = render([], use_shader=False)
    assert render([]) == base
    assert lighting.shader is None
    assert render([MaterialLight(Vec2(1000, 1000), 10, (1, 1, 1))]) == base
    assert render([MaterialLight(Vec2(88, 64), 110, (0, 0, 0))]) == base
    assert render([MaterialLight(Vec2(88, 64), 110, (1, 1, 1), illumination_gain=0)]) == base
    assert render([MaterialLight(Vec2(88, 64), 110, (1, 1, 1))]) != base
    assert render([]) == base
    # Toggle back to the original alpha shader after an active RTX frame.
    assert render([], use_shader=False) == base


@pytest.mark.parametrize('rotation', [0., 90., 217.])
def test_directional_response_rotation_alpha_and_cell_isolation(player_sprite, rotation):
    render, _ = player_sprite
    base = render([], rotation=rotation)
    source = MaterialLight(Vec2(90, 64), 110, (.5, .8, 1.5), height=40)
    right = render([source], rotation=rotation)
    left = render([msgspec.structs.replace(source, pos=Vec2(38, 64))], rotation=rotation)
    neighbor_base = render([], rotation=rotation, neighbor=True)
    neighbor_lit = render([source], rotation=rotation, neighbor=True)
    # Native alpha-aware base filtering can see an adjacent cell at rotated
    # quad edges. Isolate the new relief/rim taps from that existing sampling.
    for a, b, lit, neighbor in zip(base, neighbor_base, right, neighbor_lit, strict=True):
        if a == b:
            assert lit == neighbor
    assert [p[3] for p in base] == [p[3] for p in right] == [p[3] for p in left]
    def halves(pixels):
        delta = [p[2]-b[2] for p, b in zip(pixels, base, strict=True)]
        return [sum(v for i, v in enumerate(delta) if (i % 128 >= 64) == half) for half in (False, True)]
    assert halves(right)[1] > halves(right)[0]
    assert halves(left)[0] > halves(left)[1]


def test_camera_scale_degenerate_basis_and_budget(player_sprite):
    render, _ = player_sprite
    source = MaterialLight(Vec2(88, 64), 110, (.5, .8, 1.5), height=40)
    normal = render([source])
    zoomed = render([source], scale=2, camera=Vec2(-32.25, -32.25))
    for y in range(59, 69):
        for x in range(59, 69):
            assert normal[y*128+x] == pytest.approx(zoomed[(2*y-63)*128+(x-32)*2], abs=.002)
    degenerate = render([source], degenerate_uv=True)
    assert any(p[3] > 0 for p in degenerate)
    assert all(math.isfinite(c) for p in degenerate for c in p)
    assert render([source]*(MAX_MATERIAL_LIGHTS+1)) == render([source]*MAX_MATERIAL_LIGHTS)


@pytest.mark.parametrize('axis', [Vec2(1, 0), Vec2(-1, 0)])
def test_beam_uses_shared_energy_centroid_and_illumination_gain(player_sprite, axis):
    render, _ = player_sprite
    source = MaterialLight(Vec2(64, 40), 110, (.5, .8, 1.5), height=40, direction=axis, length=80)
    # The energy centroid of the shared ramp from the light's tail radiance to its head.
    tail = source.reflection_tail
    centroid = source.pos + axis * (80 * (1 - tail) / (6 * (1 + tail)))
    point = msgspec.structs.replace(source, pos=centroid, direction=Vec2(), length=0)
    actual = render([source])
    for a, b in zip(actual, render([point]), strict=True):
        assert a == pytest.approx(b, abs=.002)
    assert actual == render([msgspec.structs.replace(source, direction=axis*8)])
    assert actual != render([msgspec.structs.replace(source, illumination_gain=.1)])


@pytest.mark.parametrize('tint,dominant', [(rl.Color(77, 77, 255, 255), 2), (rl.Color(255, 140, 89, 255), 0)])
def test_coop_identity_survives_neutral_light(player_sprite, tint, dominant):
    render, _ = player_sprite
    base = render([], tint=tint)
    lit = render([MaterialLight(Vec2(88, 64), 110, (1, 1, 1), height=40, illumination_gain=4)], tint=tint)
    energy = [sum(p[c] for p in lit) for c in range(3)]
    assert energy[dominant] > max(v for c, v in enumerate(energy) if c != dominant) * 1.2
    assert energy[dominant] > sum(p[dominant] for p in base)


@pytest.mark.parametrize('mode', list(RtxRenderMode))
@pytest.mark.parametrize('dead', [False, True])
def test_native_layers_exclude_shadows_and_effects(mocker, headless_resources, mode, dead):
    ctx = render_ctx_for_creatures(headless_resources, [])
    player = PlayerState(index=0, pos=Vec2(64, 64), health=0 if dead else 100, shield_timer=2, muzzle_flash_alpha=.5)
    from crimson.perks import PerkId
    ctx.frame.state.perks[PerkId.RADIOACTIVE] = 1
    lighting = PlayerLighting()
    ctx = msgspec.structs.replace(ctx, frame=msgspec.structs.replace(ctx.frame, players=[player], rtx_mode=mode,
                                                                  player_lighting=lighting))
    active = False
    atlas = mocker.Mock()
    effects = mocker.Mock()
    @contextmanager
    def scope(**kwargs):
        nonlocal active
        active = True
        try:
            yield
        finally:
            active = False
    mocker.patch.object(PlayerLighting, 'scope', side_effect=scope)
    mocker.patch.object(WorldRenderCtx, '_draw_atlas_sprite', side_effect=lambda *a, **k: atlas(k['tint'], active))
    mocker.patch.object(rl, 'draw_texture_pro', side_effect=lambda *a: effects(active))
    mocker.patch.object(rl, 'begin_blend_mode')
    mocker.patch.object(rl, 'end_blend_mode')
    draw_player_trooper_sprite(ctx, headless_resources.texture(TextureId.TROOPER), player,
                               camera=Vec2(), view_scale=Vec2(1, 1), scale=1.)
    assert atlas.call_count == (2 if dead else 4)
    for call in atlas.call_args_list:
        tint, lit = call.args
        assert lit == (mode is RtxRenderMode.RTX and max(tint.r, tint.g, tint.b) > 0)
    assert effects.call_count > 0
    assert not any(call.args[0] for call in effects.call_args_list)


def test_shared_selection_and_resource_cleanup(mocker, headless_resources, tmp_path):
    ctx = render_ctx_for_creatures(headless_resources, [])
    lighting = PlayerLighting()
    ctx = msgspec.structs.replace(ctx, frame=msgspec.structs.replace(ctx.frame, rtx_mode=RtxRenderMode.RTX,
                                                                  player_lighting=lighting,
                                                                  creature_lighting=CreatureLighting()))
    light = MaterialLight(Vec2(64, 64), 100, (1, 1, 1))
    collect = mocker.patch.object(world_draw, 'collect_material_lights', return_value=[light])
    prepare = mocker.patch.object(PlayerLighting, 'prepare')
    creature_prepare = mocker.patch.object(CreatureLighting, 'prepare')
    mocker.patch.object(AlphaTestShader, 'scope', side_effect=nullcontext)
    background = mocker.patch.object(world_draw, 'draw_background')
    mocker.patch.object(world_draw, 'draw_players')
    mocker.patch.object(world_draw, 'draw_freeze_overlay')
    mocker.patch.object(world_draw, 'projectile_render')
    bonus = mocker.patch.object(world_draw, 'bonus_render')
    world_draw.draw_world(ctx)
    assert prepare.call_args.args[0] == (light,)
    assert creature_prepare.call_args.args[0] is prepare.call_args.args[0]
    collect.assert_called_once()
    assert background.call_args.kwargs["material_lights"] is prepare.call_args.args[0]
    assert bonus.call_args.kwargs["ctx"].material_lights is prepare.call_args.args[0]
    shader = rl.ffi.new('Shader *')[0]
    shader.id = 42
    restore = rl.ffi.new('Shader *')[0]
    restore.id = 9
    lighting.shader = shader
    lighting.active = True
    begin = mocker.patch.object(rl, 'begin_shader_mode')
    mocker.patch.object(rl, 'rl_draw_render_batch_active')
    with pytest.raises(ValueError), lighting.scope(restore_shader=restore):
        raise ValueError('interrupted draw')
    assert [c.args[0] for c in begin.call_args_list] == [shader, restore]
    unload = mocker.patch.object(rl, 'unload_shader')
    resources = RenderResources(tmp_path, player_lighting=lighting)
    resources.close()
    resources.close()
    unload.assert_called_once_with(shader)
    assert lighting.shader is None and not lighting.active


def test_ring_source_uses_nearest_annulus_and_finite_support(player_sprite):
    render, _ = player_sprite
    base = render([])
    ring = MaterialLight(Vec2(264, 64), 30, (1, .5, .2), ring_radius=200, height=16)
    lit = render([ring])
    assert max(abs(a[0] - b[0]) for a, b in zip(lit, base, strict=True)) > .03
    assert all(math.isfinite(c) for p in lit for c in p)
    assert render([msgspec.structs.replace(ring, pos=Vec2(64, 64))]) == base


def test_aim_ui_does_not_collect_or_prepare_player_lighting(mocker, headless_resources):
    ctx = render_ctx_for_creatures(headless_resources, [])
    ctx = msgspec.structs.replace(ctx, frame=msgspec.structs.replace(
        ctx.frame, rtx_mode=RtxRenderMode.RTX, player_lighting=PlayerLighting(),
    ))
    collect = mocker.patch.object(world_draw, 'collect_material_lights')
    prepare = mocker.patch.object(PlayerLighting, 'prepare')
    mocker.patch.object(AlphaTestShader, 'scope', side_effect=nullcontext)
    mocker.patch.object(world_draw, '_draw_aim_ui')
    world_draw.ui_render_aim_indicators(ctx, show_aim=True, aim_enhancement_fade=1.)
    collect.assert_not_called()
    prepare.assert_not_called()
