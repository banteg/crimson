from __future__ import annotations

import math
import struct
from contextlib import contextmanager

import msgspec
import pytest

from crimson.creatures.spawn import CreatureTypeId
from crimson.render.rtx import creature_lighting
from crimson.render.rtx.creature_lighting import CreatureLighting
from crimson.render.rtx.material_lights import MaterialLight
from crimson.render.rtx.mode import RtxRenderMode
from crimson.render.world import draw as world_draw
from crimson.world.render_resources import RenderResources
from grim.assets import TextureId
from grim.edr import load_float_render_texture
from grim.geom import Vec2
from grim.raylib_api import rl, rl_rectangle, rl_vector2
from grim.shaders import AlphaTestShader
from grim.texture_mode import texture_mode
from tests.support.creature_draw_capture import render_ctx_for_creatures
from tests.support.factories import make_creature_state


@pytest.mark.parametrize("mode", list(RtxRenderMode))
def test_only_rtx_bodies_use_lighting(mocker, headless_resources, mode):
    creature = make_creature_state(pos=Vec2(64, 64), type_id=CreatureTypeId.SPIDER_SP1)
    creature.hit_flash_timer = 0.1
    ctx = render_ctx_for_creatures(headless_resources, [creature])
    from grim.config import default_crimson_cfg

    config = default_crimson_cfg()
    config.display.violence_disabled = True
    lighting = CreatureLighting()
    ctx = msgspec.structs.replace(ctx, frame=msgspec.structs.replace(
        ctx.frame, rtx_mode=mode, config=config, creature_lighting=lighting,
    ))
    active = False
    draws = mocker.Mock()
    scoped_textures = []

    @contextmanager
    def scope(**kwargs):
        nonlocal active
        scoped_textures.append(kwargs["texture"])
        active = True
        try:
            yield
        finally:
            active = False

    prepare = mocker.patch.object(CreatureLighting, "prepare")
    mocker.patch.object(CreatureLighting, "scope", side_effect=scope)
    mocker.patch.object(world_draw, "draw_creature_sprite", side_effect=lambda *a, **kw: draws(kw, active))
    mocker.patch.object(world_draw, "draw_creature_overlays")
    mocker.patch.object(world_draw.rl, "begin_blend_mode")
    mocker.patch.object(world_draw.rl, "end_blend_mode")
    world_draw.draw_creatures(ctx, ctx=world_draw.WorldDrawContext())
    assert prepare.call_count == int(mode is RtxRenderMode.RTX)
    assert scoped_textures == (
        [headless_resources.texture(TextureId.SPIDER_SP1)] if mode is RtxRenderMode.RTX else []
    )
    assert draws.call_count == 3
    for call in draws.call_args_list:
        kwargs, lit = call.args
        assert lit == (mode is RtxRenderMode.RTX and not kwargs.get("shadow") and not kwargs.get("hit_flash"))


def test_lazy_lifecycle_and_exception_restore(mocker, tmp_path):
    lighting = CreatureLighting()
    load = mocker.patch.object(rl, "load_shader_from_memory")
    lighting.prepare([], camera=Vec2(), view_scale=Vec2(1, 1))
    load.assert_not_called()
    begin = mocker.patch.object(rl, "begin_shader_mode")
    unload = mocker.patch.object(rl, "unload_shader")
    shader = rl.ffi.new("Shader *")[0]
    shader.id = 42
    restore = rl.ffi.new("Shader *")[0]
    restore.id = 9
    texture = rl.ffi.new("Texture *")[0]
    texture.id = 10
    thickness = rl.ffi.new("Texture *")[0]
    thickness.id = 11
    lighting.shader = shader
    lighting.active = True
    lighting.locations["u_thickness"] = 12
    lighting.thickness_textures[texture.id] = thickness
    mocker.patch.object(rl, "set_shader_value_texture")
    mocker.patch.object(rl, "rl_draw_render_batch_active")
    unload_texture = mocker.patch.object(rl, "unload_texture")
    with pytest.raises(ValueError), lighting.scope(texture=texture, restore_shader=restore):
        raise ValueError("drawing interrupted")
    assert [call.args[0] for call in begin.call_args_list] == [shader, restore]
    resources = RenderResources(tmp_path, creature_lighting=lighting)
    resources.close()
    resources.close()
    unload.assert_called_once_with(shader)
    unload_texture.assert_called_once_with(thickness)
    assert not lighting.thickness_textures
    assert lighting.shader is None and not lighting.active


@pytest.fixture
def lit_sprite(raylib_context):
    # Eight-by-eight atlas, with an opaque disk and a small protruding limb.
    image = rl.gen_image_color(256, 256, rl.BLANK)
    rl.image_draw_circle(image, 16, 16, 10, rl.Color(70, 55, 40, 255))
    rl.image_draw_rectangle(image, 24, 15, 8, 3, rl.Color(70, 55, 40, 255))
    texture = rl.load_texture_from_image(image)
    rl.unload_image(image)
    target = load_float_render_texture(128, 128)
    lighting = CreatureLighting()
    alpha = AlphaTestShader()

    def render(lights, *, use_shader=True, rotation=0.0, scale=1.0, camera=Vec2(), neighbor=False,
               degenerate_uv=False, textured=False, relief_ramp=None, pigment: tuple[int, int, int] = (70, 55, 40)):
        other = rl.gen_image_color(256, 256, rl.BLANK)
        rl.image_draw_circle(other, 16, 16, 10, rl.Color(*pigment, 255))
        rl.image_draw_rectangle(other, 24, 15, 8, 3, rl.Color(*pigment, 255))
        if textured:
            for y in range(10, 23):
                for x in range(10, 23):
                    value = 30 + (x - 10) * 10 + (y - 10) * 5
                    if relief_ramp is not None:
                        value = round(120 + (x - 15.5) * relief_ramp.x + (y - 15.5) * relief_ramp.y)
                    rl.image_draw_pixel(other, x, y, rl.Color(value, value, value, 255))
        if neighbor:
            rl.image_draw_rectangle(other, 32, 0, 32, 32, rl.Color(255, 0, 0, 255))
        rl.update_texture(texture, other.data)
        rl.unload_image(other)
        rl.set_texture_filter(texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR if textured
                              else rl.TextureFilter.TEXTURE_FILTER_POINT)
        lighting.prepare(lights, camera=camera, view_scale=Vec2(scale, scale))
        with texture_mode(target):
            rl.clear_background(rl.BLANK)
            with alpha.scope():
                def draw():
                    pos = (Vec2(64, 64) + camera) * scale
                    source = rl_rectangle(20, 16, 0, 0) if degenerate_uv else rl_rectangle(0, 0, 32, 32)
                    rl.draw_texture_pro(texture, source,
                                        rl_rectangle(pos.x, pos.y, 32*scale, 32*scale),
                                        rl_vector2(16*scale, 16*scale), rotation, rl.WHITE)
                if use_shader:
                    with lighting.scope(texture=texture, restore_shader=alpha.shader):
                        draw()
                else:
                    draw()
        img = rl.load_image_from_texture(target.texture)
        try:
            rl.image_format(img, rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32)
            return list(struct.iter_unpack("ffff", bytes(rl.ffi.buffer(img.data, 128*128*16))))
        finally:
            rl.unload_image(img)

    try:
        yield render, lighting
    finally:
        lighting.close()
        alpha.close()
        rl.unload_texture(texture)
        rl.unload_render_texture(target)


def test_zero_and_out_of_range_lights_preserve_base_pixels(lit_sprite):
    render, lighting = lit_sprite
    base = render([], use_shader=False)
    assert render([]) == base
    assert lighting.shader is None
    assert not lighting.thickness_textures
    assert render([MaterialLight(Vec2(1000, 1000), 10, (1, 1, 1))]) == base
    assert render([MaterialLight(Vec2(64, 64), 100, (0, 0, 0))]) == base
    assert render([]) == base  # A previous lit frame cannot leak into the next one.


def test_degenerate_uv_basis_keeps_lighting_finite(lit_sprite, monkeypatch):
    from crimson.render.rtx import creature_lighting

    render, lighting = lit_sprite
    # A nonzero destination still rasterizes when all UVs sample one opaque texel.
    # This exercises the singular basis instead of a zero-area quad with no fragments.
    base = render([], degenerate_uv=True)
    lit = render([MaterialLight(Vec2(90, 64), 110, (1.4, .68, .2), height=40)], degenerate_uv=True)
    assert any(p[3] > 0 for p in base)
    assert all(math.isfinite(channel) for pixel in lit for channel in pixel)
    assert [p[3] for p in lit] == [p[3] for p in base]
    assert sum(p[0] for p in lit) > sum(p[0] for p in base) + 1
    # The singular mapping must produce the same shading as an explicit identity basis.
    fragment = creature_lighting.CREATURE_FRAGMENT
    start = fragment.index("    float determinant =")
    end = fragment.index("    vec2 wp =", start)
    monkeypatch.setattr(creature_lighting, "CREATURE_FRAGMENT",
                        fragment[:start] + "    mat2 rot = mat2(1.0);\n" + fragment[end:])
    lighting.close()
    identity = render([MaterialLight(Vec2(90, 64), 110, (1.4, .68, .2), height=40)], degenerate_uv=True)
    assert lit == identity


@pytest.mark.parametrize("rotation", [0., 90., 217.])
def test_rim_follows_world_light_and_preserves_alpha(lit_sprite, rotation):
    render, _lighting = lit_sprite
    base = render([], rotation=rotation)
    right = render([MaterialLight(Vec2(90, 64), 110, (1.4, .68, .2), height=40)], rotation=rotation)
    left = render([MaterialLight(Vec2(38, 64), 110, (1.4, .68, .2), height=40)], rotation=rotation)
    assert [p[3] for p in base] == [p[3] for p in right] == [p[3] for p in left]
    def halves(pixels):
        delta = [p[0]-b[0] for p, b in zip(pixels, base, strict=True)]
        assert min(delta) >= -0.001
        return [sum(v for i, v in enumerate(delta) if (i % 128 >= 64) == half) for half in (False, True)]
    assert halves(right)[1] > halves(right)[0]
    assert halves(left)[0] > halves(left)[1]


def test_camera_scale_and_adjacent_atlas_frame(lit_sprite):
    render, _lighting = lit_sprite
    lights = [MaterialLight(Vec2(88, 64), 110, (.5, .8, 1.5), height=40)]
    normal = render(lights)
    # Doubling the view and moving its origin preserves the world-space illumination.
    zoomed = render(lights, scale=2, camera=Vec2(-32.25, -32.25))
    for x in range(59, 69):
        a = normal[63*128+x]
        # Offset the zoomed camera by a quarter unit to align pixel centers.
        b = zoomed[63*128+(x-32)*2]
        assert a[:3] == pytest.approx(b[:3], abs=.002)
    neighbor = render(lights, neighbor=True)
    # Pixel centers near the right edge of frame zero must not read frame one's alpha.
    for y in range(128):
        for x in range(48, 80):
            i=y*128+x
            assert normal[i] == neighbor[i]


@pytest.mark.parametrize("rotation", [0., 90.])
def test_textured_relief_is_independent_of_framebuffer_scale(lit_sprite, rotation):
    render, _lighting = lit_sprite
    lights = [MaterialLight(Vec2(88, 64), 110, (.5, .8, 1.5), height=40)]
    normal = render(lights, textured=True, rotation=rotation)
    zoomed = render(lights, textured=True, rotation=rotation, scale=2, camera=Vec2(-32.25, -32.25))
    for y in range(59, 69):
        for x in range(59, 69):
            # Render-target rows run upward; align the world-space sample centers.
            a = normal[y*128+x]
            b = zoomed[(2*y-63)*128+(x-32)*2]
            assert a == pytest.approx(b, abs=.002)


@pytest.mark.parametrize("rotation", [0., 90., 217.])
@pytest.mark.parametrize("axis", [Vec2(1, 0), Vec2(0, 1)], ids=["u", "v"])
def test_bright_relief_faces_downhill_light(lit_sprite, rotation, axis):
    render, _lighting = lit_sprite
    angle = math.radians(rotation)
    uphill = Vec2(axis.x * math.cos(angle) - axis.y * math.sin(angle),
                  axis.x * math.sin(angle) + axis.y * math.cos(angle))
    # Align the sprite center to a pixel center. Opposite ramps have identical
    # albedo here, so only their normals can change the lighting response.
    options = {"textured": True, "rotation": rotation, "camera": Vec2(.5, .5)}
    center = 63 * 128 + 64
    rising = axis * 10
    falling = axis * -10
    base_rising = render([], relief_ramp=rising, **options)[center]
    base_falling = render([], relief_ramp=falling, **options)[center]
    assert base_rising == pytest.approx(base_falling, abs=.001)
    for direction in (-1, 1):
        light = MaterialLight(Vec2(64, 64) + uphill * (24 * direction), 110, (1, 1, 1), height=40)
        lit_rising = render([light], relief_ramp=rising, **options)[center]
        lit_falling = render([light], relief_ramp=falling, **options)[center]
        # A height field's normal points downhill: reversing the light must
        # reverse which ramp is brighter, for either atlas axis and any rotation.
        assert (lit_falling[0] - lit_rising[0]) * direction > .005


@pytest.mark.parametrize("offset", [0., 1.])
def test_relief_cannot_read_neighboring_atlas_cells(lit_sprite, offset):
    render, _lighting = lit_sprite
    lights = [MaterialLight(Vec2(88, 64), 110, (.5, .8, 1.5), height=40)]
    camera = Vec2(offset, 0)
    normal = render(lights, camera=camera)
    neighbor = render(lights, camera=camera, neighbor=True)
    assert normal == neighbor


@pytest.mark.parametrize("direction", [-1., 1.])
@pytest.mark.parametrize("along_fraction,gain", [(0., .2), (.5, .6), (1., 1.)])
def test_beam_taper_matches_point_radiance_once(lit_sprite, direction, along_fraction, gain):
    render, _lighting = lit_sprite
    rgb = (.5, .8, 1.5)
    # Along this pixel column the closest beam point is exactly the reference point.
    source = Vec2(64.5, 40)
    beam = MaterialLight(source + Vec2(direction * (0.5 - along_fraction) * 256, 0),
                         110, rgb, height=40, direction=Vec2(direction, 0), length=256)
    point = MaterialLight(source, 110, tuple(c * gain for c in rgb), height=40)
    actual = render([beam])
    expected = render([point])
    for y in range(56, 72):
        assert actual[y*128+64] == pytest.approx(expected[y*128+64], abs=.002)


def test_multiple_emitters_and_light_budget(lit_sprite):
    render, _lighting = lit_sprite
    red = MaterialLight(Vec2(86, 64), 110, (1.4, 0, 0), height=40)
    blue = MaterialLight(Vec2(42, 64), 110, (0, 0, 1.4), height=40)
    base = render([])
    red_only = render([red])
    blue_only = render([blue])
    both = render([red, blue])
    def energy(pixels, channel):
        return sum(p[channel]-b[channel] for p, b in zip(pixels, base, strict=True))
    assert energy(both, 0) > energy(blue_only, 0) + 1
    assert energy(both, 2) > energy(red_only, 2) + 1
    assert render([red]*16 + [blue]) == render([red]*16)


@pytest.mark.parametrize("rgb,channel", [((1.4, 0, 0), 0), ((0, 0, 1.4), 2)])
@pytest.mark.parametrize("light_x", [38, 90], ids=["far-side-limb", "near-side-limb"])
def test_transmission_lights_thin_parts_on_either_side_of_light(lit_sprite, monkeypatch, rgb, channel, light_x):
    render, lighting = lit_sprite
    light = MaterialLight(Vec2(light_x, 64), 110, rgb, height=40)
    actual = render([light])
    lighting.close()
    fragment = creature_lighting.CREATURE_FRAGMENT
    reference = fragment.replace(
        "const float TRANSMISSION_STRENGTH = 1.4;",
        "const float TRANSMISSION_STRENGTH = 0.0;",
    )
    assert reference != fragment
    monkeypatch.setattr(creature_lighting, "CREATURE_FRAGMENT", reference)
    baseline = render([light])
    assert [p[3] for p in actual] == [p[3] for p in baseline]
    limb = 63 * 128 + 77
    core = 63 * 128 + 64
    gain = actual[limb][channel] - baseline[limb][channel]
    assert gain > .02
    assert actual[core][channel] - baseline[core][channel] < gain * .5
    # Pigment modulates the source spectrum without emitting unlit channels.
    for other in set(range(3)) - {channel}:
        assert actual[limb][other] == pytest.approx(baseline[limb][other], abs=.001)


def test_transmission_retains_pigment_and_restrains_black_parts(lit_sprite, monkeypatch):
    render, lighting = lit_sprite
    light = MaterialLight(Vec2(38, 64), 110, (1, 1, 1), height=40)
    pigments = [(0, 0, 0), (255, 255, 255), (180, 30, 30), (30, 180, 30)]
    limb = 63 * 128 + 77
    actual = [render([light], pigment=color)[limb] for color in pigments]
    lighting.close()
    fragment = creature_lighting.CREATURE_FRAGMENT
    reference = fragment.replace(
        "const float TRANSMISSION_STRENGTH = 1.4;",
        "const float TRANSMISSION_STRENGTH = 0.0;",
    )
    assert reference != fragment
    monkeypatch.setattr(creature_lighting, "CREATURE_FRAGMENT", reference)
    baseline = [render([light], pigment=color)[limb] for color in pigments]
    gain = [
        [a[c] ** 2.2 - b[c] ** 2.2 for c in range(3)]
        for a, b in zip(actual, baseline, strict=True)
    ]
    assert 0 < gain[0][0] < gain[1][0] * .1
    assert gain[2][0] > gain[2][1] * 3
    assert gain[3][1] > gain[3][0] * 3
