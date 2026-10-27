from __future__ import annotations

import math
import struct
from collections.abc import Sequence

import msgspec
import pytest

from crimson.render.rtx.continuous_beam_shaders import CONTINUOUS_BEAM_GLSL
from crimson.render.rtx.lighting_shaders import LIGHT_VISIBILITY_GLSL
from crimson.render.rtx.material_lights import MaterialLight
from crimson.render.rtx.material_shaders import GROUND_FRAGMENT
from crimson.render.rtx.materials import _integer, _shader, _uniform
from crimson.render.rtx.reflection_occlusion import (
    CROWD_BODIES,
    PENUMBRA_WIDTH,
    BodyVolume,
    ReflectionOcclusion,
    build_occlusion_grid,
)
from grim.edr import load_float_render_texture
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.texture_mode import texture_mode


def _pixel(target: rl.RenderTexture) -> tuple[float, float, float, float]:
    image = rl.load_image_from_texture(target.texture)
    try:
        rl.image_format(image, rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32)
        return struct.unpack("ffff", bytes(rl.ffi.buffer(image.data, 16)))
    finally:
        rl.unload_image(image)


def _probe_shader(main: str) -> rl.Shader:
    return _shader(
        "#version 330\n#define BEAM_VISIBILITY_PASS\n#define MAX_SPEC_LIGHTS 32\nout vec4 finalColor;\n"
        + LIGHT_VISIBILITY_GLSL + CONTINUOUS_BEAM_GLSL + main,
    )


@pytest.mark.parametrize(("body_y", "lit"), [(20., "full"), (29., "partial"), (60., "dark")])
def test_body_does_not_shadow_a_light_inside_or_against_it(raylib_context, body_y: float, lit: str) -> None:
    # A muzzle flash pressed into a packed crowd: the creature it sits in must not cut its pool along a straight line.
    shader = _probe_shader("""
    void main() {
        float point = sourceVisibility(vec3(64., 100., 0.), vec3(64., 20., 20.), .5, vec2(1e19));
        finalColor = vec4(point, 0., 0., 1.);
    }
    """)
    target = load_float_render_texture(2, 2)
    renderer = ReflectionOcclusion()
    source = MaterialLight(Vec2(64., 20.), 200., (1., 1., 1.), height=20., source_width=.5, beam_profile=(16., 3.1, 1.05))
    body = BodyVolume(Vec2(64., body_y), Vec2(8., 8.), 40., 0.)
    try:
        grid = build_occlusion_grid([body], [source], width=128., height=128.)
        texture = renderer.upload(grid)
        _uniform(shader, "u_occlusion_grid", [grid.origin.x, grid.origin.y, float(grid.columns), float(grid.rows)])
        _uniform(shader, "u_occlusion_cell_size", [grid.cell_size])
        _integer(shader, "u_dynamic_shadows", 1)
        with texture_mode(target):
            rl.begin_shader_mode(shader)
            rl.set_shader_value_texture(shader, rl.get_shader_location(shader, "u_occlusion_tex"), texture)
            rl.draw_rectangle(0, 0, 2, 2, rl.WHITE)
            rl.end_shader_mode()
        for value in _pixel(target)[:1]:
            if lit == "full":
                assert value == pytest.approx(1.)
            elif lit == "partial":
                assert .05 < value < .95
            else:
                assert value < .05
    finally:
        renderer.close()
        rl.unload_shader(shader)
        rl.unload_render_texture(target)


def test_receiver_inside_the_body_around_the_light_stays_lit(raylib_context) -> None:
    # Ground under the creature a beam's head sits in: its own body spares the light there too.
    shader = _probe_shader("""
    void main() {
        float point = sourceVisibility(vec3(64., 64., 0.), vec3(64., 64., 24.), .5, vec2(1e19));
        finalColor = vec4(point, 0., 0., 1.);
    }
    """)
    target = load_float_render_texture(2, 2)
    renderer = ReflectionOcclusion()
    source = MaterialLight(Vec2(64., 64.), 200., (1., 1., 1.), height=24., source_width=.5, beam_profile=(16., 3.1, 1.05))
    body = BodyVolume(Vec2(64., 64.), Vec2(16., 16.), 40., 0.)
    try:
        grid = build_occlusion_grid([body], [source], width=128., height=128.)
        texture = renderer.upload(grid)
        _uniform(shader, "u_occlusion_grid", [grid.origin.x, grid.origin.y, float(grid.columns), float(grid.rows)])
        _uniform(shader, "u_occlusion_cell_size", [grid.cell_size])
        _integer(shader, "u_dynamic_shadows", 1)
        with texture_mode(target):
            rl.begin_shader_mode(shader)
            rl.set_shader_value_texture(shader, rl.get_shader_location(shader, "u_occlusion_tex"), texture)
            rl.draw_rectangle(0, 0, 2, 2, rl.WHITE)
            rl.end_shader_mode()
        assert _pixel(target)[0] == pytest.approx(1.)
    finally:
        renderer.close()
        rl.unload_shader(shader)
        rl.unload_render_texture(target)


def test_penumbra_stops_widening_past_the_penumbra_width(raylib_context) -> None:
    shader = _probe_shader("""
    uniform vec4 u_widths;
    void main() {
        vec3 receiver = vec3(70., 110., 0.), source = vec3(64., 20., 30.);
        finalColor = vec4(sourceVisibility(receiver, source, u_widths.x, vec2(1e19)),
                          sourceVisibility(receiver, source, u_widths.y, vec2(1e19)),
                          sourceVisibility(receiver, source, u_widths.z, vec2(1e19)), 1.);
    }
    """)
    target = load_float_render_texture(2, 2)
    renderer = ReflectionOcclusion()
    wide = MaterialLight(Vec2(64., 20.), 200., (1., 1., 1.), height=30., source_width=PENUMBRA_WIDTH * 4)
    body = BodyVolume(Vec2(64., 80.), Vec2(6., 6.), 30., 0.)
    try:
        grid = build_occlusion_grid([body], [wide], width=128., height=128.)
        texture = renderer.upload(grid)
        _uniform(shader, "u_occlusion_grid", [grid.origin.x, grid.origin.y, float(grid.columns), float(grid.rows)])
        _uniform(shader, "u_occlusion_cell_size", [grid.cell_size])
        _uniform(shader, "u_widths", [1., PENUMBRA_WIDTH, PENUMBRA_WIDTH * 4, 0.])
        _integer(shader, "u_dynamic_shadows", 1)
        with texture_mode(target):
            rl.begin_shader_mode(shader)
            rl.set_shader_value_texture(shader, rl.get_shader_location(shader, "u_occlusion_tex"), texture)
            rl.draw_rectangle(0, 0, 2, 2, rl.WHITE)
            rl.end_shader_mode()
        narrow, capped, widest = _pixel(target)[:3]
        assert narrow != pytest.approx(capped, abs=.01)
        assert widest == pytest.approx(capped)
    finally:
        renderer.close()
        rl.unload_shader(shader)
        rl.unload_render_texture(target)






def test_point_visibility_fades_keeps_all_casters_and_preserves_ray_state(raylib_context) -> None:
    shader = _probe_shader("""
    uniform vec4 u_owner;
    void main() {
        vec3 receiver = vec3(64., 110., 0.), source = vec3(64., 20., 24.);
        float before = sourceVisibility(receiver, source, .5, u_owner.xy);
        float section = sourceVisibility(receiver, source, .5, u_owner.xy);
        float after = sourceVisibility(receiver, source, .5, u_owner.xy);
        finalColor = vec4(section, before, after, 1.);
    }
    """)
    target = load_float_render_texture(2, 2)
    renderer = ReflectionOcclusion()
    source = MaterialLight(Vec2(64., 20.), 200., (1., 1., 1.), height=24., source_width=4.5, beam_profile=(16., 3.1, 1.05))
    body = BodyVolume(Vec2(64., 64.), Vec2(1.5, 1.5), 40., 0., owner=Vec2(64., 64.))

    def sample(bodies: Sequence[BodyVolume], *, shadows: bool = True, owner: Vec2 = Vec2(1e19, 1e19)):
        grid = build_occlusion_grid(bodies, [source], width=128., height=128.)
        texture = renderer.upload(grid)
        _uniform(shader, "u_occlusion_grid", [grid.origin.x, grid.origin.y, float(grid.columns if shadows else 0), float(grid.rows)])
        _uniform(shader, "u_occlusion_cell_size", [grid.cell_size])
        _uniform(shader, "u_owner", [owner.x, owner.y, 0., 0.])
        _integer(shader, "u_dynamic_shadows", int(shadows))
        with texture_mode(target):
            rl.begin_shader_mode(shader)
            rl.set_shader_value_texture(shader, rl.get_shader_location(shader, "u_occlusion_tex"), texture)
            rl.draw_rectangle(0, 0, 2, 2, rl.WHITE)
            rl.end_shader_mode()
        value = _pixel(target)
        assert value[1] == value[2]  # A later reflection ray must see the original path.
        return value[0]

    try:
        clear = sample([])
        blocked = sample([body])
        assert clear == 1.
        assert 0. <= blocked < .95
        half = msgspec.structs.replace(body, opacity=.5)
        assert sample([half]) == pytest.approx((clear + blocked) / 2., abs=.002)
        assert sample([half] * CROWD_BODIES) == pytest.approx(sample([half]), abs=.002)
        # A late stronger caster must not disappear behind an arbitrary budget.
        assert sample([half] * (CROWD_BODIES - 1) + [body]) == pytest.approx(blocked, abs=.002)
        assert sample([body] + [half] * (CROWD_BODIES - 1)) == pytest.approx(blocked, abs=.002)
        # Past that the cell is a crowd: a medium that darkens with its density and still spares its own bodies.
        sparse, dense = sample([half] * (CROWD_BODIES + 1)), sample([half] * 70)
        assert clear > sparse > dense > 0.
        assert sample([body] + [half] * 69) < dense
        # The receiver's own cell: a crowd standing wholly inside it does not shade the receiving body.
        inside = msgspec.structs.replace(half, pos=Vec2(80., 90.), owner=Vec2(80., 90.))
        assert sample([inside] * 70) < clear
        assert sample([inside] * 70, owner=inside.owner) == clear
        assert sample([body], shadows=False) == clear
        assert sample([body], owner=body.owner) == clear
        assert sample([msgspec.structs.replace(body, opacity=0.)]) == clear
    finally:
        renderer.close()
        rl.unload_shader(shader)
        rl.unload_render_texture(target)


def test_default_ground_shader_compiles(raylib_context) -> None:
    shader = _shader(GROUND_FRAGMENT)
    rl.unload_shader(shader)




def test_beam_falloff_integrals_match_the_summed_falloff(raylib_context) -> None:
    shader = _probe_shader("""
    uniform vec4 u_probe; // b, R, lo, hi
    void main() {
        float b = u_probe.x, R = u_probe.y, lo = u_probe.z, hi = u_probe.w;
        vec2 closed = beamPiece(.3, .02, lo, hi, b, R);
        vec2 summed = vec2(0.);
        for (int i = 0; i < 4096; i++) {
            float u = lo + (hi - lo) * (float(i) + .5) / 4096.;
            float falloff = pow(max(0., 1. - sqrt(u * u + b * b) / R), 2.) * (.3 + .02 * u) * (hi - lo) / 4096.;
            summed += vec2(falloff, falloff * u);
        }
        finalColor = vec4(closed, summed);
    }
    """)
    target = load_float_render_texture(2, 2)
    try:
        for probe in ((1e-3, 150., -40., 60.), (30., 150., -100., 100.), (90., 195., 10., 120.), (5., 240., -200., -20.)):
            _uniform(shader, "u_probe", list(probe))
            with texture_mode(target):
                rl.begin_shader_mode(shader)
                rl.draw_rectangle(0, 0, 2, 2, rl.WHITE)
                rl.end_shader_mode()
            energy, moment, summed_energy, summed_moment = _pixel(target)
            assert energy == pytest.approx(summed_energy, rel=2e-3)
            assert moment == pytest.approx(summed_moment, rel=2e-3, abs=1e-2)
    finally:
        rl.unload_shader(shader)
        rl.unload_render_texture(target)


@pytest.mark.parametrize("body_y,body_height,shadowed", [(60., 12., True), (60., 40., True), (0., 40., False)])
def test_analytic_beam_fan_matches_sampled_emitter_with_ordinary_lists(
    raylib_context, body_y, body_height, shadowed,
):
    shader = _probe_shader("""
    void main() {
        vec3 receiver = vec3(64., 100., 0.), center = vec3(64., 20., 24.);
        beamFanVisibility(receiver, center, 4.5, vec2(1., 0.), 20.);
        float analytic = dot(beam_bins[0] + beam_bins[1], vec4(.125));
        float reference = 0.;
        for (int along = 0; along < 32; ++along) {
            float offset = ((float(along) + .5) / 32. * 2. - 1.) * 20.;
            for (int across = 0; across < 8; ++across) {
                float transverse = ((float(across) + .5) / 8. * 2. - 1.) * 4.5;
                reference += sourceVisibility(receiver, center + vec3(offset, transverse, 0.), .1, vec2(1e19));
            }
        }
        finalColor = vec4(analytic, reference / 256., 0., 1.);
    }
    """)
    target = load_float_render_texture(2, 2)
    renderer = ReflectionOcclusion()
    source = MaterialLight(Vec2(64, 20), 200, (1, 1, 1), height=24, source_width=4.5, length=40,
                           direction=Vec2(1, 0))
    body = BodyVolume(Vec2(64, body_y), Vec2(8, 10), body_height, 0)
    try:
        grid = build_occlusion_grid([body], [source], width=128, height=128)
        texture = renderer.upload(grid)
        _uniform(shader, "u_occlusion_grid", [grid.origin.x, grid.origin.y, float(grid.columns), float(grid.rows)])
        _uniform(shader, "u_occlusion_cell_size", [grid.cell_size])
        with texture_mode(target):
            rl.begin_shader_mode(shader)
            rl.set_shader_value_texture(shader, rl.get_shader_location(shader, "u_occlusion_tex"), texture)
            rl.draw_rectangle(0, 0, 2, 2, rl.WHITE)
            rl.end_shader_mode()
        analytic, reference = _pixel(target)[:2]
        assert 0 < analytic < 1 if shadowed else analytic == 1
        assert analytic == pytest.approx(reference, abs=.08)
    finally:
        renderer.close()
        rl.unload_shader(shader)
        rl.unload_render_texture(target)


def test_extended_beam_penumbra_is_directional_and_duplicate_lists_are_idempotent(raylib_context):
    shader = _probe_shader("""
    void main() {
        vec3 receiver = vec3(64., 120., 0.), center = vec3(64., 20., 24.);
        beamFanVisibility(receiver, center, .5, vec2(1., 0.), 40.);
        float across = dot(beam_bins[0] + beam_bins[1], vec4(.125));
        beamFanVisibility(receiver, center, .5, vec2(0., 1.), 40.);
        float along = dot(beam_bins[0] + beam_bins[1], vec4(.125));
        float point = sourceVisibility(receiver, center, .5, vec2(1e19));
        finalColor = vec4(across, along, point, 1.);
    }
    """)
    target = load_float_render_texture(2, 2)
    renderer = ReflectionOcclusion()
    source = MaterialLight(Vec2(64, 20), 200, (1, 1, 1), height=24, source_width=.5, length=80,
                           direction=Vec2(1, 0))
    body = BodyVolume(Vec2(64, 90), Vec2(5, 5), 40, 0)
    try:
        grid = build_occlusion_grid([body], [source], width=128, height=128)
        assert grid.references > 1  # the blocker overlaps several ordinary lists
        texture = renderer.upload(grid)
        _uniform(shader, "u_occlusion_grid", [grid.origin.x, grid.origin.y, float(grid.columns), float(grid.rows)])
        _uniform(shader, "u_occlusion_cell_size", [grid.cell_size])
        with texture_mode(target):
            rl.begin_shader_mode(shader)
            rl.set_shader_value_texture(shader, rl.get_shader_location(shader, "u_occlusion_tex"), texture)
            rl.draw_rectangle(0, 0, 2, 2, rl.WHITE)
            rl.end_shader_mode()
        across, along, point = _pixel(target)[:3]
        assert point < .05 and along < .05
        assert across > along + .3  # a nearest point cannot reproduce this penumbra
        # Repeated references and even overlapping identical bodies retain min
        # occlusion, rather than incorrectly multiplying the same shadow.
        before = (across, along, point)
        grid = build_occlusion_grid([body, body], [source], width=128, height=128)
        texture = renderer.upload(grid)
        with texture_mode(target):
            rl.begin_shader_mode(shader)
            rl.set_shader_value_texture(shader, rl.get_shader_location(shader, "u_occlusion_tex"), texture)
            rl.draw_rectangle(0, 0, 2, 2, rl.WHITE)
            rl.end_shader_mode()
        assert _pixel(target)[:3] == pytest.approx(before, abs=.001)
    finally:
        renderer.close()
        rl.unload_shader(shader)
        rl.unload_render_texture(target)



def test_analytic_fan_finds_blocker_outside_the_center_ray_cells(raylib_context):
    shader = _probe_shader("""
    void main() {
        vec3 receiver = vec3(64., 240., 0.), center = vec3(64., 20., 24.);
        beamFanVisibility(receiver, center, 4.5, vec2(1., 0.), 160.);
        float analytic = dot(beam_bins[0] + beam_bins[1], vec4(.125));
        float reference = 0.;
        for (int along = 0; along < 256; ++along) {
            float offset = ((float(along) + .5) / 256. * 2. - 1.) * 160.;
            for (int across = 0; across < 8; ++across) {
                float transverse = ((float(across) + .5) / 8. * 2. - 1.) * 4.5;
                reference += sourceVisibility(receiver, center + vec3(offset, transverse, 0.), .1, vec2(1e19));
            }
        }
        finalColor = vec4(analytic, reference / 2048., sourceVisibility(receiver, center, .1, vec2(1e19)), 1.);
    }
    """)
    target = load_float_render_texture(2, 2)
    renderer = ReflectionOcclusion()
    source = MaterialLight(Vec2(64, 20), 400, (1, 1, 1), height=24, source_width=4.5, length=320,
                           direction=Vec2(1, 0))
    body = BodyVolume(Vec2(160, 70), Vec2(16, 10), 40, 0)
    try:
        grid = build_occlusion_grid([body], [source], width=256, height=256)
        # The center ray cannot discover this blocker through ordinary lists.
        column = math.floor((64 - grid.origin.x) / grid.cell_size)
        assert all(grid.values[(row * grid.columns + column) * 4 + 1] == 0 for row in range(grid.rows))
        texture = renderer.upload(grid)
        _uniform(shader, "u_occlusion_grid", [grid.origin.x, grid.origin.y, float(grid.columns), float(grid.rows)])
        _uniform(shader, "u_occlusion_cell_size", [grid.cell_size])
        with texture_mode(target):
            rl.begin_shader_mode(shader)
            rl.set_shader_value_texture(shader, rl.get_shader_location(shader, "u_occlusion_tex"), texture)
            rl.draw_rectangle(0, 0, 2, 2, rl.WHITE)
            rl.end_shader_mode()
        analytic, reference, center = _pixel(target)[:3]
        assert center == 1 and analytic < .95
        assert analytic == pytest.approx(reference, abs=.05)
    finally:
        renderer.close()
        rl.unload_shader(shader)
        rl.unload_render_texture(target)
