from __future__ import annotations

import math
import struct
from contextlib import contextmanager

import msgspec
import pytest

from crimson.creatures.spawn import CreatureTypeId
from crimson.render.rtx import creature_lighting
from crimson.render.rtx.creature_lighting import CreatureLighting
from crimson.render.rtx.material_lights import MAX_MATERIAL_LIGHTS, MaterialLight
from crimson.render.rtx.mode import RtxRenderMode
from crimson.render.world import draw as world_draw
from crimson.render.world.creatures import draw_centered_quad
from crimson.world.render_resources import RenderResources
from grim.assets import TextureId
from grim.edr import load_float_render_texture
from grim.geom import Vec2
from grim.raylib_api import rl, rl_color, rl_rectangle, rl_vector2
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
    lighting.locations["u_thickness"] = 12
    lighting.locations["u_ice"] = 13
    lighting.locations["u_ice_frozen"] = 14
    lighting.locations["u_creature_type"] = 15
    lighting.thickness_textures[texture.id] = thickness
    mocker.patch.object(rl, "set_shader_value_texture")
    mocker.patch.object(rl, "set_shader_value")
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
    assert lighting.shader is None


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
               degenerate_uv=False, textured=False, relief_ramp=None, occlusion=None, shadows=True, ambient=1., center=Vec2(64, 64), target_override=None, type_id=None, pigment: tuple[int, int, int] = (70, 55, 40)):
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
        lighting.prepare(lights, camera=camera, view_scale=Vec2(scale, scale), occlusion=occlusion, shadows=shadows, ambient=ambient)
        render_target = target if target_override is None else target_override
        with texture_mode(render_target, linear=True):
            rl.clear_background(rl.BLANK)
            with alpha.scope():
                def draw():
                    pos = (center + camera) * scale
                    source = rl_rectangle(20, 16, 0, 0) if degenerate_uv else rl_rectangle(0, 0, 32, 32)
                    if use_shader:
                        # As the world draws lit bodies: the quad carries its center for the shadows.
                        draw_centered_quad(texture, source, pos, 32 * scale, 32 * scale, math.radians(rotation), rl_color(255, 255, 255, 255))
                    else:
                        rl.draw_texture_pro(texture, source,
                                            rl_rectangle(pos.x, pos.y, 32*scale, 32*scale),
                                            rl_vector2(16*scale, 16*scale), rotation, rl.WHITE)
                if use_shader:
                    with lighting.scope(texture=texture, restore_shader=alpha.shader, type_id=type_id):
                        draw()
                else:
                    draw()
        img = rl.load_image_from_texture(render_target.texture)
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
    assert not lighting.thickness_textures
    assert render([MaterialLight(Vec2(1000, 1000), 10, (1, 1, 1))]) == base
    assert render([MaterialLight(Vec2(64, 64), 100, (0, 0, 0))]) == base
    assert render([]) == base  # A previous lit frame cannot leak into the next one.


@pytest.mark.parametrize("type_id", [CreatureTypeId.LIZARD, CreatureTypeId.ALIEN, CreatureTypeId.SPIDER_SP1, CreatureTypeId.SPIDER_SP2])
@pytest.mark.parametrize("ambient", [.6, 1.])
def test_ambient_species_material_survives_an_unreachable_light(lit_sprite, type_id, ambient):
    render, _ = lit_sprite
    options = {"ambient": ambient, "type_id": type_id, "textured": True}
    unlit = render([], **options)
    assert unlit != render([], ambient=ambient, textured=True)
    assert render([MaterialLight(Vec2(320, 64), 8, (1., 1., 1.))], **options) == unlit
    assert render([], **options) == unlit


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
                        fragment[:start] + "    mat2 rot = mat2(1.0); vec2 owner = vec2(1e19);\n" + fragment[end:])
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
def test_beam_reflection_taper_matches_point_radiance_once(lit_sprite, direction, along_fraction, gain):
    render, _lighting = lit_sprite
    rgb = (.5, .8, 1.5)
    # Along this pixel column the closest beam point is exactly the reference point.
    source = Vec2(64.5, 40)
    # The taper is the light's own: a linear ramp from its tail radiance to its head.
    beam = MaterialLight(source + Vec2(direction * (0.5 - along_fraction) * 256, 0),
                         110, rgb, height=40, direction=Vec2(direction, 0), length=256, illumination_gain=0,
                         reflection_tail=.2)
    point = MaterialLight(source, 110, tuple(c * gain for c in rgb), height=40, illumination_gain=0)
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
    assert render([red]*MAX_MATERIAL_LIGHTS + [blue]) == render([red]*MAX_MATERIAL_LIGHTS)


def test_independent_diffuse_and_specular_response(lit_sprite):
    import msgspec

    render, _ = lit_sprite
    base = render([])
    light = MaterialLight(Vec2(88, 64), 1, (1, .5, .1), illumination_gain=0, reflection_radius=110)
    reflected = render([light])
    assert reflected != base
    assert [p[3] for p in reflected] == [p[3] for p in base]
    assert render([msgspec.structs.replace(light, reflection_gain=0)]) == base
    diffuse = render([msgspec.structs.replace(light, radius=110, illumination_gain=1, reflection_gain=0)])
    assert diffuse != base and diffuse != reflected


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
    assert gain > .005
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
    gain = [[a[c] - b[c] for c in range(3)] for a, b in zip(actual, baseline, strict=True)]
    assert 0 < gain[0][0] < gain[1][0] * .1
    assert gain[2][0] > gain[2][1] * 3
    assert gain[3][1] > gain[3][0] * 3


@pytest.mark.parametrize("illumination,radius,length", [(0., 110., 0.), (0., 110., 128.), (1., 1., 0.)],
                         ids=["reflection-only-point", "reflection-only-tracer", "outside-illumination-reach"])
def test_transmission_obeys_illumination_channel(lit_sprite, monkeypatch, illumination, radius, length):
    render, lighting = lit_sprite
    source = MaterialLight(Vec2(88, 64), radius, (1.4, .3, .1), height=40,
                           direction=Vec2(1, 0), length=length,
                           illumination_gain=illumination, reflection_radius=110)
    base = render([], use_shader=False)
    transmission_on = render([source])
    illuminated = msgspec.structs.replace(source, radius=110, illumination_gain=1)
    positive_control = render([illuminated])
    lighting.close()
    fragment = creature_lighting.CREATURE_FRAGMENT
    reference = fragment.replace("const float TRANSMISSION_STRENGTH = 1.4;",
                                 "const float TRANSMISSION_STRENGTH = 0.0;")
    assert reference != fragment
    monkeypatch.setattr(creature_lighting, "CREATURE_FRAGMENT", reference)
    transmission_off = render([source])
    # Actual GPU pixels: zero transmission, but the reflected catch remains.
    assert transmission_on == transmission_off
    assert transmission_on != base
    assert [p[3] for p in transmission_on] == [p[3] for p in base]
    assert positive_control != render([illuminated])


@pytest.mark.parametrize("rotation", [0., 37., 143., 271.])
@pytest.mark.parametrize("scale", [.73, 1., 1.37, 1.8])
@pytest.mark.parametrize("owner", [Vec2(64, 64), Vec2(984, 874)])
def test_own_body_is_excluded_without_excluding_nearby_creatures(lit_sprite, rotation, scale, owner):
    from crimson.render.rtx.reflection_occlusion import BodyVolume, ReflectionOcclusion, build_occlusion_grid

    render, _ = lit_sprite
    source = MaterialLight(owner + Vec2(29, 0), 110, (1.4, .68, .2), height=24)
    body = BodyVolume(owner, Vec2(12, 10), 28, math.radians(rotation), owner=owner)
    occlusion = ReflectionOcclusion()
    camera = Vec2(64 / scale + .37, 64 / scale - .23) - owner
    options = {"rotation": rotation, "scale": scale, "camera": camera, "center": owner}
    try:
        clear = render([source], **options)
        occlusion.upload(build_occlusion_grid([body], [source], width=1024, height=1024))
        own = render([source], occlusion=occlusion, **options)
        assert own == clear
        # A different owner very close to this sprite must remain a blocker: from the quad's corners it shadows the
        # side whose rays cross it.
        neighbor = msgspec.structs.replace(body, owner=owner + Vec2(.1, 0))
        occlusion.upload(build_occlusion_grid([neighbor], [source], width=1024, height=1024))
        blocked = render([source], occlusion=occlusion, **options)
        assert sum(p[0] for p in blocked) < sum(p[0] for p in clear) * .997
        assert render([source], occlusion=occlusion, shadows=False, **options) == clear
        assert render([], occlusion=occlusion, ambient=.6, **options) == render([], ambient=.6, **options)
    finally:
        occlusion.close()


def test_crowd_alone_shades_a_creature(lit_sprite):
    from crimson.render.rtx.reflection_occlusion import (
        CROWD_BODIES,
        BodyVolume,
        ReflectionOcclusion,
        build_occlusion_grid,
    )

    render, _ = lit_sprite
    source = MaterialLight(Vec2(124, 64), 110, (1.4, .68, .2), height=24)
    # A crowd standing between the light and the sprite, which the grid keeps as density alone.
    crowd = [BodyVolume(Vec2(96, 64), Vec2(12, 10), 28, 0, owner=Vec2(96, 64))] * (CROWD_BODIES + 1)
    occlusion = ReflectionOcclusion()
    try:
        clear = render([source])
        grid = build_occlusion_grid(crowd, [source], width=1024, height=1024)
        assert grid.body_count == 0
        occlusion.upload(grid)
        blocked = render([source], occlusion=occlusion)
        assert sum(p[0] for p in blocked) < sum(p[0] for p in clear) * .99
    finally:
        occlusion.close()


def test_corner_shadows_hold_as_corners_leave_the_lights_reach(lit_sprite):
    from crimson.render.rtx.reflection_occlusion import BodyVolume, ReflectionOcclusion, build_occlusion_grid

    render, _ = lit_sprite
    owner = Vec2(64, 64)
    # A neighbor's body shadows the quad's far side, whose pixels the light still reaches and whose corners'
    # traces they interpolate, so those corners keep their shadow as they cross the light's reach.
    body = BodyVolume(owner + Vec2(.1, 0), Vec2(12, 10), 28, 0., owner=owner + Vec2(.1, 0))
    occlusion = ReflectionOcclusion()
    edge = 48 + math.sqrt(40**2 - 16**2)  # the light's x with the far corners at its reach

    def frame(x: float) -> list[tuple[float, float, float, float]]:
        light = MaterialLight(Vec2(x, 64), 40, (1.4, .68, .2), height=24)
        occlusion.upload(build_occlusion_grid([body], [light], width=1024, height=1024))
        return render([light], occlusion=occlusion, center=owner)

    try:
        inside, outside = frame(edge - .002), frame(edge + .002)
        assert max(abs(a[0] - b[0]) for a, b in zip(inside, outside, strict=True)) < .005
    finally:
        occlusion.close()


def test_unlit_ambient_fill_preserves_alpha_without_loading_thickness(lit_sprite):
    render, lighting = lit_sprite
    native = render([], use_shader=False)
    filled = render([], ambient=.6)
    assert not lighting.thickness_textures
    assert [p[3] for p in filled] == [p[3] for p in native]
    assert sum(p[0] for p in filled) == pytest.approx(sum(p[0] for p in native) * .6, rel=.002)


@pytest.mark.parametrize("gain", [(1., 0.), (0., 1.), (1., 1.)])
def test_creature_source_axis_matches_point_fallback_and_normalized_beam(lit_sprite, gain):
    render, _ = lit_sprite
    source = MaterialLight(Vec2(90, 64), 110, (1.4, .68, .2), height=24,
                           illumination_gain=gain[0], reflection_gain=gain[1])
    point = render([source])
    for axis in (Vec2(), Vec2(.001, 0)):
        assert render([msgspec.structs.replace(source, direction=axis, length=128)]) == point
    unit = msgspec.structs.replace(source, direction=Vec2(.6, .8), length=40)
    expected = render([unit])
    scaled = render([msgspec.structs.replace(unit, direction=Vec2(6, 8))])
    for a, b in zip(scaled, expected, strict=True):
        assert a == pytest.approx(b, abs=.001)


@pytest.mark.parametrize("reach", [0., -1.])
@pytest.mark.parametrize("reflection_gain", [0., 1.])
def test_creature_nonpositive_reflection_reach_is_disabled_and_finite(lit_sprite, reach, reflection_gain):
    render, _ = lit_sprite
    source = MaterialLight(Vec2(90, 64), 110, (1.4, .68, .2), height=24, reflection_gain=0)
    expected = render([source])
    actual = render([msgspec.structs.replace(source, reflection_radius=reach, reflection_gain=reflection_gain)])
    assert actual == expected
    assert all(math.isfinite(c) for p in actual for c in p)


def test_empty_grid_disables_creature_traversal_and_unlit_uniform_arrays(lit_sprite, mocker):
    from crimson.render.rtx.reflection_occlusion import ReflectionOcclusion, build_occlusion_grid

    render, lighting = lit_sprite
    source = MaterialLight(Vec2(90, 64), 110, (1.4, .68, .2), height=24)
    expected = render([source])
    empty = ReflectionOcclusion()
    grid_uploads = []
    original = rl.set_shader_value

    def capture(shader, location, value, kind):
        if location == lighting.locations.get("u_occlusion_grid"):
            grid_uploads.append(tuple(rl.ffi.cast("float *", value)[i] for i in range(4)))
        return original(shader, location, value, kind)

    mocker.patch.object(rl, "set_shader_value", side_effect=capture)
    arrays = mocker.spy(rl, "set_shader_value_v")
    try:
        empty.upload(build_occlusion_grid([], [source], width=128, height=128))
        assert render([source], occlusion=empty) == expected
        assert grid_uploads[-1][2] == 0
        arrays.reset_mock()
        render([], ambient=.6, occlusion=empty)
        arrays.assert_not_called()
    finally:
        empty.close()


def test_annular_source_lights_the_front_and_leaves_distant_center_unlit(lit_sprite):
    render, _ = lit_sprite
    base = render([])
    ring = MaterialLight(Vec2(264, 64), 30, (1, .5, .2), ring_radius=200,
                         height=16, source_width=8, reflection_radius=30)
    lit = render([ring])
    assert max(abs(a[0] - b[0]) for a, b in zip(lit, base, strict=True)) > .03
    assert all(math.isfinite(c) for p in lit for c in p)
    centered = msgspec.structs.replace(ring, pos=Vec2(64, 64))
    assert render([centered]) == base


def test_continuous_beam_shadows_follow_beam_centroid_and_head_halo(lit_sprite):
    from crimson.render.rtx.reflection_occlusion import BodyVolume, ReflectionOcclusion, build_occlusion_grid

    render, _ = lit_sprite
    # Long beam along +x from tail x=64 to head x=320 (center x=192, static centroid x~235).
    beam = MaterialLight(
        Vec2(192, 20), 155, (1.4, .68, .2), height=24, direction=Vec2(1, 0), length=256,
        source_width=3, illumination_gain=4, reflection_gain=1, reflection_radius=155,
        reflection_tail=0., beam_profile=(16., 3.1, 1.35),
    )
    occlusion = ReflectionOcclusion()
    try:
        # Creature beside the tail (64, 64): beamAtReceiver's lit centroid sits near x~145, not the static x~235.
        clear = render([beam], center=Vec2(64, 64))
        # Blocker on the ray toward the actual lit centroid shadows the creature.
        lit_blocker = BodyVolume(Vec2(105, 42), Vec2(10, 10), 32, 0., owner=Vec2(105, 42))
        occlusion.upload(build_occlusion_grid([lit_blocker], [beam], width=1024, height=1024))
        blocked = render([beam], occlusion=occlusion, center=Vec2(64, 64))
        assert sum(p[0] for p in blocked) < sum(p[0] for p in clear) * .85

        # Blocker far along the ray to the static centroid (235, 20), past the lit stretch, must not shadow it.
        far_blocker = BodyVolume(Vec2(190, 31), Vec2(8, 8), 32, 0., owner=Vec2(190, 31))
        occlusion.upload(build_occlusion_grid([far_blocker], [beam], width=1024, height=1024))
        unblocked = render([beam], occlusion=occlusion, center=Vec2(64, 64))
        assert sum(p[0] for p in unblocked) == pytest.approx(sum(p[0] for p in clear), rel=.01)

        # Creature past half_length + radius + corner_radius without the head halo, yet lit by the head halo.
        from crimson.render.rtx.continuous_beam import prepare_beam_lights

        halo_beam = msgspec.structs.replace(beam, pos=Vec2(192, 64), radius=100, reflection_radius=100,
                                            beam_profile=(64., 6., 1.35))
        # Segment head ends at x=320; head_width ~32 extends emitting head to ~352.
        # At x=445, owner-to-320 minus quad corner radius (22.6) is 102.4 >= 100, so without the head halo
        # creature_visibility.glsl culled the quad to unshadowed even though its disk (x=435..445) is lit.
        owner = Vec2(445, 64)
        cam = Vec2(64, 64) - owner
        base_halo = render([], center=owner, camera=cam)
        clear_halo = render([halo_beam], center=owner, camera=cam)
        assert sum(p[0] for p in clear_halo) > sum(p[0] for p in base_halo) + .05
        halo_blocker = BodyVolume(Vec2(390, 64), Vec2(16, 16), 36, 0., owner=Vec2(390, 64))
        _, grid_lights = prepare_beam_lights([halo_beam])
        occlusion.upload(build_occlusion_grid([halo_blocker], grid_lights, width=1024, height=1024))
        blocked_halo = render([halo_beam], occlusion=occlusion, center=owner, camera=cam)
        assert sum(p[0] for p in blocked_halo) < sum(p[0] for p in clear_halo) - .02
    finally:
        occlusion.close()


def test_beam_specular_shadow_traces_nearest_segment_and_stays_stable_when_illumination_drops(lit_sprite):
    from crimson.render.rtx.reflection_occlusion import BodyVolume, ReflectionOcclusion, build_occlusion_grid

    render, _ = lit_sprite
    # Long Ion beam along +x from tail x=64 to head x=320 (center x=192).
    # Creature at (350, 128) sits beyond the head: nearest segment point is the head (320, 64),
    # while diffuse beamAtReceiver centroid lies back along the shaft near x~288.
    beam = MaterialLight(
        Vec2(192, 64), 195, (.55, .82, 1.45), height=24, direction=Vec2(1, 0), length=256,
        source_width=3, illumination_gain=4, reflection_gain=2, reflection_radius=195,
        reflection_tail=0., beam_profile=(35.2, 6.82, 1.05), beam_ion=True,
    )
    reflection_only = msgspec.structs.replace(beam, illumination_gain=0.)
    fading = msgspec.structs.replace(beam, illumination_gain=1e-4)
    owner = Vec2(350, 128)
    cam = Vec2(64, 64) - owner
    # Blocker beside the shaft blocks the ray to the diffuse centroid (~288, 64) but leaves the head (320, 64) clear.
    shaft_blocker = BodyVolume(Vec2(297, 73), Vec2(13, 7), 32, 0., owner=Vec2(297, 73))
    # Blocker directly between the creature and the beam head blocks specular highlights.
    head_blocker = BodyVolume(Vec2(335, 96), Vec2(10, 10), 32, 0., owner=Vec2(335, 96))
    occlusion = ReflectionOcclusion()
    try:
        base = render([], center=owner, camera=cam)
        clear_ref = render([reflection_only], center=owner, camera=cam)
        assert max(a[2] - b[2] for a, b in zip(clear_ref, base, strict=True)) > .02

        # Shaft blocker must not suppress the reflection-only highlight from the unblocked beam head.
        occlusion.upload(build_occlusion_grid([shaft_blocker], [reflection_only], width=1024, height=1024))
        shaft_ref = render([reflection_only], occlusion=occlusion, center=owner, camera=cam)
        assert shaft_ref == clear_ref

        # With diffuse active too, the shaft blocker shadows diffuse while keeping the full specular highlight.
        clear_full = render([beam], center=owner, camera=cam)
        occlusion.upload(build_occlusion_grid([shaft_blocker], [beam], width=1024, height=1024))
        shaft_full = render([beam], occlusion=occlusion, center=owner, camera=cam)
        assert sum(p[2] for p in shaft_full) < sum(p[2] for p in clear_full) * .7
        assert sum(p[2] for p in shaft_full) >= sum(p[2] for p in clear_ref) - .005

        # Blocker on the creature-to-head ray shadows the specular highlight.
        occlusion.upload(build_occlusion_grid([head_blocker], [reflection_only], width=1024, height=1024))
        head_ref = render([reflection_only], occlusion=occlusion, center=owner, camera=cam)
        assert sum(p[2] for p in head_ref) < sum(p[2] for p in clear_ref) - .05

        # Dropping illumination budget from 1e-4 to 0 must not pop specular shadows for either blocker.
        for blocker in (shaft_blocker, head_blocker):
            occlusion.upload(build_occlusion_grid([blocker], [fading], width=1024, height=1024))
            fading_img = render([fading], occlusion=occlusion, center=owner, camera=cam)
            occlusion.upload(build_occlusion_grid([blocker], [reflection_only], width=1024, height=1024))
            dropped_img = render([reflection_only], occlusion=occlusion, center=owner, camera=cam)
            for a, b in zip(fading_img, dropped_img, strict=True):
                assert a == pytest.approx(b, abs=.002)
    finally:
        occlusion.close()


def test_beam_shadow_stays_bounded_near_illumination_cutoff(lit_sprite):
    from crimson.render.rtx.continuous_beam import prepare_beam_lights
    from crimson.render.rtx.reflection_occlusion import BodyVolume, ReflectionOcclusion, build_occlusion_grid

    render, _ = lit_sprite
    # 256-unit Ion Rifle beam along +x from x=0 to x=256 (center x=128, head halo to ~272).
    # Place the creature so one quad corner sits right at the reach boundary (b ~ 185.7 vs R=195) where float32
    # cancellation in beamFalloffIntegrals can otherwise throw the centroid hundreds of units past the head.
    beam = MaterialLight(
        Vec2(128, 100), 195, (.55, .82, 1.45), height=24, direction=Vec2(1, 0), length=256,
        source_width=3, illumination_gain=6, reflection_gain=1, reflection_radius=195,
        reflection_tail=0., beam_profile=(35.2, 6.82, 1.05), beam_ion=True,
    )
    owner = Vec2(328, 270)
    cam = Vec2(64, 64) - owner
    # Blocker far past the beam head (~x=550), which only an out-of-span cancelled centroid could ever cross.
    bogus_blocker = BodyVolume(Vec2(550, 210), Vec2(40, 40), 40, 0., owner=Vec2(550, 210))
    occlusion = ReflectionOcclusion()
    try:
        clear = render([beam], center=owner, camera=cam)
        _, grid_lights = prepare_beam_lights([beam])
        wide = msgspec.structs.replace(grid_lights[0], radius=500, reflection_radius=500)
        occlusion.upload(build_occlusion_grid([bogus_blocker], [wide], width=1024, height=1024))
        actual = render([beam], occlusion=occlusion, center=owner, camera=cam)
        assert actual == clear

        # Smooth transition across low irradiance: moving a creature by 0.001 units near the reach cutoff
        # must not snap diffuse or specular visibility across an intervening blocker.
        blocker = BodyVolume(Vec2(276, 196), Vec2(8, 8), 36, 0., owner=Vec2(276, 196))
        ref_beam = msgspec.structs.replace(beam, reflection_radius=240)
        _, ref_grid = prepare_beam_lights([ref_beam])
        occlusion.upload(build_occlusion_grid([blocker], ref_grid, width=1024, height=1024))
        step_a = render([ref_beam], occlusion=occlusion, center=Vec2(328, 270.000), camera=Vec2(64 - 328, 64 - 270))
        step_b = render([ref_beam], occlusion=occlusion, center=Vec2(328, 270.001), camera=Vec2(64 - 328, 64 - 270))
        assert max(abs(a[2] - b[2]) for a, b in zip(step_a, step_b, strict=True)) < .005
    finally:
        occlusion.close()
