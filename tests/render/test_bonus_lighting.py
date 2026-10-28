from __future__ import annotations

import math
import struct
from contextlib import contextmanager, nullcontext

import msgspec
import pytest

from crimson.bonuses import BonusId
from crimson.bonuses.pool import BonusEntry
from crimson.render.rtx import bonus_lighting as module
from crimson.render.rtx.bonus_lighting import BonusLighting
from crimson.render.rtx.material_lights import MAX_MATERIAL_LIGHTS, MaterialLight
from crimson.render.rtx.mode import RtxRenderMode
from crimson.render.world import bonuses, draw
from crimson.world.render_resources import RenderResources
from grim.edr import load_float_render_texture
from grim.geom import Vec2
from grim.raylib_api import rl, rl_rectangle, rl_vector2
from grim.shaders import AlphaTestShader
from grim.texture_mode import texture_mode
from tests.support.creature_draw_capture import render_ctx_for_creatures


def test_classic_and_rtx_keep_pickup_order_geometry_and_fades(mocker, headless_resources):
    ctx = render_ctx_for_creatures(headless_resources, [])
    for i, kind in enumerate((BonusId.FIRE_BULLETS, BonusId.WEAPON, BonusId.NUKE)):
        ctx.frame.state.bonus_pool.entries[i] = BonusEntry(
            bonus_id=kind, pos=Vec2(40+i*20, 60), time_left=.3, time_max=10., amount=1,
        )
    lighting = BonusLighting()
    prepare = mocker.patch.object(BonusLighting, 'prepare')
    passes = mocker.Mock()
    active_pass = None

    @contextmanager
    def scope(**kwargs):
        nonlocal active_pass
        passes(**kwargs)
        active_pass = kwargs['pass_id']
        try:
            yield
        finally:
            active_pass = None

    mocker.patch.object(BonusLighting, 'pass_scope', side_effect=scope)
    draws = mocker.Mock()

    def draw(texture, src, dst, origin, rotation, tint):
        draws(texture.id, (src.x, src.y, src.width, src.height), (dst.x, dst.y, dst.width, dst.height),
              (origin.x, origin.y), rotation, (tint.r, tint.g, tint.b, tint.a), active_pass)

    mocker.patch.object(bonuses.rl, 'draw_texture_pro', side_effect=draw)
    classic = msgspec.structs.replace(ctx, frame=msgspec.structs.replace(ctx.frame, bonus_lighting=lighting))
    bonuses.draw_bonus_pickups(classic, camera=Vec2(), view_scale=Vec2(1, 1), scale=1., alpha=.7)
    before = draws.call_args_list[:]
    prepare.assert_not_called()
    passes.assert_not_called()
    draws.reset_mock()
    rtx = msgspec.structs.replace(classic, frame=msgspec.structs.replace(classic.frame, rtx_mode=RtxRenderMode.RTX))
    bonuses.draw_bonus_pickups(rtx, camera=Vec2(), view_scale=Vec2(1, 1), scale=1., alpha=.7)
    prepare.assert_called_once()
    assert [c.args[:-1] for c in before] == [c.args[:-1] for c in draws.call_args_list]
    assert [c.args[-1] for c in draws.call_args_list] == [0, 1, 0, 0, 1, 1]
    assert passes.call_args_list[-1].kwargs['grid'] == (4., 8.)
    assert passes.call_args_list[-1].kwargs['shell_center'] == Vec2(60, 60)


def test_empty_pool_does_not_prepare_shader(mocker, headless_resources):
    ctx = render_ctx_for_creatures(headless_resources, [])
    ctx = msgspec.structs.replace(ctx, frame=msgspec.structs.replace(
        ctx.frame, rtx_mode=RtxRenderMode.RTX, bonus_lighting=BonusLighting(),
    ))
    prepare = mocker.patch.object(BonusLighting, 'prepare')
    bonuses.draw_bonus_pickups(ctx, camera=Vec2(), view_scale=Vec2(1, 1), scale=1.)
    prepare.assert_not_called()


def test_bonus_render_distinguishes_uncollected_and_empty_lights(mocker, headless_resources):
    render_ctx = render_ctx_for_creatures(headless_resources, [])
    render_ctx = msgspec.structs.replace(render_ctx, frame=msgspec.structs.replace(
        render_ctx.frame, rtx_mode=RtxRenderMode.RTX, bonus_lighting=BonusLighting(),
    ))
    render_ctx.frame.state.bonus_pool.entries[0] = BonusEntry(
        bonus_id=BonusId.FIRE_BULLETS, pos=Vec2(40, 60), time_left=5., time_max=10.,
    )
    light = MaterialLight(Vec2(40, 60), 100, (1, .5, .2))
    collect = mocker.patch.object(bonuses, "collect_material_lights", return_value=[light])
    prepare = mocker.patch.object(BonusLighting, "prepare")
    mocker.patch.object(BonusLighting, "pass_scope", side_effect=lambda **kw: nullcontext())
    mocker.patch.object(rl, "draw_texture_pro")
    for name in ("draw_bonus_hover_labels", "draw_particle_pool", "secondary_detonation_pass",
                 "draw_sprite_effect_pool", "draw_effect_pool"):
        mocker.patch.object(draw, name)

    ctx = draw.build_draw_context(render_ctx, entity_alpha=1.)
    draw.bonus_render(render_ctx, ctx=ctx)
    collect.assert_called_once()
    assert prepare.call_args.args[0] == [light]

    for selected in ((), (light,)):
        collect.reset_mock()
        draw.bonus_render(render_ctx, ctx=msgspec.structs.replace(ctx, material_lights=selected))
        collect.assert_not_called()
        assert prepare.call_args.args[0] is selected


def test_owned_lifecycle_and_exception_restore(mocker, tmp_path):
    lighting = BonusLighting()
    assert lighting.shader is None
    shader = rl.ffi.new('Shader *')[0]
    shader.id = 42
    restore = rl.ffi.new('Shader *')[0]
    restore.id = 9
    lighting.shader = shader
    lighting.locations = dict.fromkeys(('u_pass', 'u_grid', 'u_shell_center'), 1)
    begin = mocker.patch.object(rl, 'begin_shader_mode')
    mocker.patch.object(rl, 'rl_draw_render_batch_active')
    mocker.patch.object(rl, 'set_shader_value')
    unload = mocker.patch.object(rl, 'unload_shader')
    with pytest.raises(ValueError), lighting.pass_scope(
        pass_id=1, grid=(4., 4.), shell_center=Vec2(64, 64), restore_shader=restore,
    ):
        raise ValueError('interrupted')
    assert [c.args[0] for c in begin.call_args_list] == [shader, restore]
    owner = RenderResources(tmp_path, bonus_lighting=lighting)
    owner.close()
    owner.close()
    unload.assert_called_once_with(shader)
    assert lighting.shader is None and not lighting.locations


@pytest.fixture
def lit_bonus(raylib_context):
    image = rl.gen_image_color(128, 128, rl.BLANK)
    texture = rl.load_texture_from_image(image)
    rl.unload_image(image)
    target = load_float_render_texture(128, 128)
    lighting = BonusLighting()
    alpha = AlphaTestShader()

    def render(lights, *, pass_id=1, size=32., rotation=0., camera=Vec2(), scale=1.,
               neighbor=False, grid=(4., 4.), color=(70, 55, 40), source_shader=True, relief_ramp=None):
        image = rl.gen_image_color(128, 128, rl.BLANK)
        height = int(128/grid[1])
        rl.image_draw_rectangle(image, 0, 0, 32, height, rl.Color(color[0], color[1], color[2], 255))
        if relief_ramp is not None:
            for y in range(height//2 - 6, height//2 + 7):
                for x in range(10, 23):
                    value = round(120 + (x - 15.5) * relief_ramp.x + (y - (height - 1)/2) * relief_ramp.y)
                    rl.image_draw_pixel(image, x, y, rl.Color(value, value, value, 255))
        if neighbor:
            rl.image_draw_rectangle(image, 32, 0, 32, height, rl.Color(255, 0, 255, 255))
        rl.update_texture(texture, image.data)
        rl.unload_image(image)
        rl.set_texture_filter(texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR if relief_ramp is not None
                              else rl.TextureFilter.TEXTURE_FILTER_POINT)
        lighting.prepare(lights, camera=camera, view_scale=Vec2(scale, scale))
        pos = (Vec2(64, 64)+camera)*scale
        with texture_mode(target, linear=True):
            rl.clear_background(rl.BLANK)
            with alpha.scope():
                def draw():
                    rl.draw_texture_pro(texture, rl_rectangle(0, 0, 32, height),
                                        rl_rectangle(pos.x, pos.y, size*scale, size*scale*height/32),
                                        rl_vector2(size*scale/2, size*scale*height/64), rotation, rl.WHITE)
                if source_shader:
                    with lighting.pass_scope(pass_id=pass_id, grid=grid, shell_center=Vec2(64, 64),
                                             restore_shader=alpha.shader):
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


def test_unlit_and_out_of_range_icons_preserve_original_pixels(lit_bonus):
    render, _ = lit_bonus
    baseline = render([], source_shader=False)
    assert render([]) == baseline
    assert render([MaterialLight(Vec2(1000, 1000), 10, (1, 1, 1))]) == baseline
    lit = render([MaterialLight(Vec2(80, 80), 100, (1.4, .68, .2))])
    assert lit != baseline
    assert [p[3] for p in lit] == [p[3] for p in baseline]
    assert all(math.isfinite(c) for p in lit for c in p)
    assert render([]) == baseline


@pytest.mark.parametrize('grid', [(4., 4.), (4., 8.)], ids=['bonus', 'weapon'])
@pytest.mark.parametrize('rotation', [0., 90., 217.])
@pytest.mark.parametrize('axis', [Vec2(1, 0), Vec2(0, 1)], ids=['u', 'v'])
def test_bright_emblem_relief_faces_downhill_light(lit_bonus, grid, rotation, axis):
    render, _ = lit_bonus
    angle = math.radians(rotation)
    uphill = Vec2(axis.x * math.cos(angle) - axis.y * math.sin(angle),
                  axis.x * math.sin(angle) + axis.y * math.cos(angle))
    # Pixel-center alignment cancels the emblem's dome slope. Opposing ramps
    # have identical center albedo and coating, isolating their relief normals.
    options = {'grid': grid, 'rotation': rotation, 'camera': Vec2(.5, .5)}
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
        # Raised height tilts the normal downhill on either atlas axis; swapping
        # the light must swap which ramp is brighter, including rectangular cells.
        assert (lit_falling[0] - lit_rising[0]) * direction > .005


@pytest.mark.parametrize('pass_id', [0, 1])
@pytest.mark.parametrize('offset', [0., 1.])
def test_atlas_isolation(lit_bonus, pass_id, offset):
    render, _ = lit_bonus
    lights = [MaterialLight(Vec2(90, 64), 110, (.5, .8, 1.5), height=40)]
    assert render(lights, pass_id=pass_id, camera=Vec2(offset, 0)) == render(
        lights, pass_id=pass_id, camera=Vec2(offset, 0), neighbor=True,
    )


def test_coating_normal_stays_on_shell_during_icon_pulse_rotation_and_weapon_stretch(lit_bonus, monkeypatch):
    # Instrument the production normal calculation so foil shading cannot hide coat movement.
    fragment = module.BONUS_FRAGMENT.replace(
        '    vec3 base_lin = base.rgb;',
        '    finalColor = vec4(N_dome*.5+.5, 1.0); return;\n    vec3 base_lin = base.rgb;',
    )
    assert fragment != module.BONUS_FRAGMENT
    monkeypatch.setattr(module, 'BONUS_FRAGMENT', fragment)
    render, lighting = lit_bonus
    lighting.close()
    lights = [MaterialLight(Vec2(90, 64), 110, (.5, .8, 1.5), height=40)]
    baseline = render(lights)
    for size, rotation, grid in [(24., 0., (4., 4.)), (24., 23., (4., 4.)), (60., 0., (4., 8.))]:
        actual = render(lights, size=size, rotation=rotation, grid=grid)
        for y in range(57, 71):
            for x in range(57, 71):
                assert actual[y*128+x] == pytest.approx(baseline[y*128+x], abs=.001)


def test_weapon_overhang_has_foil_light_but_no_shell_coating(lit_bonus, monkeypatch):
    render, lighting = lit_bonus
    lights = [MaterialLight(Vec2(88, 64), 110, (.5, .8, 1.5), height=40)]
    actual = render(lights, size=60., grid=(4., 8.))
    fragment = module.BONUS_FRAGMENT.replace('    vec3 R = reflect(-V, N);',
        '    rim_and_caustic = vec3(0); return vec3(0);\n    vec3 R = reflect(-V, N);')
    monkeypatch.setattr(module, 'BONUS_FRAGMENT', fragment)
    lighting.close()
    foil = render(lights, size=60., grid=(4., 8.))
    assert any(actual[y*128+68] != foil[y*128+68] for y in range(58, 70))
    for y in range(58, 70):
        assert actual[y*128+86] == foil[y*128+86]


def test_light_budget_and_framebuffer_scale(lit_bonus):
    render, _ = lit_bonus
    light = MaterialLight(Vec2(88, 64), 110, (.5, .8, 1.5), height=40)
    assert render([light]*MAX_MATERIAL_LIGHTS) == render(
        [light]*MAX_MATERIAL_LIGHTS+[MaterialLight(Vec2(64, 64), 100, (9, 0, 0))],
    )
    normal = render([light])
    zoomed = render([light], scale=2., camera=Vec2(-32.25, -32.25))
    for y in range(59, 69):
        for x in range(59, 69):
            assert normal[y*128+x] == pytest.approx(zoomed[(2*y-63)*128+(x-32)*2], abs=.002)


def test_shell_light_direction_and_shader_reopen(lit_bonus):
    render, lighting = lit_bonus
    base = render([], pass_id=0)
    right_light = MaterialLight(Vec2(100, 64), 110, (1.4, .68, .2), height=40)
    right = render([right_light], pass_id=0)
    left = render([MaterialLight(Vec2(28, 64), 110, (1.4, .68, .2), height=40)], pass_id=0)

    def energy(pixels, right_half):
        return sum(p[0]-b[0] for i, (p, b) in enumerate(zip(pixels, base, strict=True))
                   if (i % 128 >= 64) == right_half)

    assert energy(right, True) > energy(right, False)
    assert energy(left, False) > energy(left, True)
    assert [p[3] for p in base] == [p[3] for p in right] == [p[3] for p in left]
    lighting.close()
    assert render([right_light], pass_id=0) == right


@pytest.mark.parametrize("pass_id", [0, 1])
def test_reflection_only_source_preserves_shell_and_icon_alpha(lit_bonus, pass_id):
    import msgspec

    render, _ = lit_bonus
    base = render([], pass_id=pass_id)
    light = MaterialLight(Vec2(88, 64), 1, (1, .5, .1), illumination_gain=0, reflection_radius=110)
    reflected = render([light], pass_id=pass_id)
    assert reflected != base
    assert [p[3] for p in reflected] == [p[3] for p in base]
    assert render([msgspec.structs.replace(light, reflection_gain=0)], pass_id=pass_id) == base


def test_annular_source_lights_the_front_and_leaves_distant_center_unlit(lit_bonus):
    render, _ = lit_bonus
    base = render([])
    ring = MaterialLight(Vec2(264, 64), 30, (1, .5, .2), ring_radius=200,
                         height=16, source_width=8, reflection_radius=30)
    lit = render([ring])
    assert max(abs(a[0] - b[0]) for a, b in zip(lit, base, strict=True)) > .03
    assert all(math.isfinite(c) for p in lit for c in p)
    centered = msgspec.structs.replace(ring, pos=Vec2(64, 64))
    assert render([centered]) == base
