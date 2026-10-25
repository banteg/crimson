from __future__ import annotations

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
        "#version 330\n#define CONTINUOUS_BEAM\n#define MAX_SPEC_LIGHTS 32\nout vec4 finalColor;\n"
        + LIGHT_VISIBILITY_GLSL + CONTINUOUS_BEAM_GLSL + main,
    )


def test_beam_chord_matches_analytic_sphere_coverage(raylib_context) -> None:
    shader = _probe_shader("""
    uniform vec4 u_probe;
    void main() {
        float value = beamChordCoverage(
            vec3(0., 0., -2.), vec3(0., 0., 4.), vec3(1., 0., 0.), u_probe.x);
        finalColor = vec4(value, value, value, 1.);
    }
    """)
    target = load_float_render_texture(2, 2)

    def sample(halfspan: float) -> float:
        _uniform(shader, "u_probe", [halfspan, 0., 0., 0.])
        with texture_mode(target):
            rl.begin_shader_mode(shader)
            rl.draw_rectangle(0, 0, 2, 2, rl.WHITE)
            rl.end_shader_mode()
        return _pixel(target)[0]

    try:
        assert sample(1.) == pytest.approx(1.)
        assert sample(4.) == pytest.approx(3. ** -.5, abs=.0005)
        assert sample(.01) == pytest.approx(1.)
    finally:
        rl.unload_shader(shader)
        rl.unload_render_texture(target)


@pytest.mark.parametrize(("body_y", "body_height", "shadowed"), [(60., 12., True), (60., 40., True), (0., 40., False)])
def test_projected_visibility_matches_sampled_reference(
    raylib_context, body_y: float, body_height: float, shadowed: bool,
) -> None:
    shader = _probe_shader("""
    void main() {
        vec3 receiver = vec3(64., 100., 0.);
        vec3 center = vec3(64., 20., 24.);
        vec2 axis = vec2(1., 0.), transverse_axis = vec2(0., 1.);
        float projected = sectionVisibility(receiver, center, 4.5, axis, 20., vec2(1e19));
        float reference = 0.;
        for (int along = 0; along < 16; along++) {
            float offset = ((float(along) + .5) / 16. * 2. - 1.) * 20.;
            for (int across = 0; across < 4; across++) {
                float transverse = ((float(across) + .5) / 4. * 2. - 1.) * 4.5;
                vec3 source = center + vec3(axis * offset + transverse_axis * transverse, 0.);
                reference += sourceVisibility(receiver, source, .1, vec2(1e19));
            }
        }
        finalColor = vec4(projected, reference / 64., 0., 1.);
    }
    """)
    target = load_float_render_texture(2, 2)
    renderer = ReflectionOcclusion()
    source = MaterialLight(Vec2(64., 20.), 200., (1., 1., 1.), height=24., source_width=4.5, beam_profile=(16., 3.1, 1.05))
    body = BodyVolume(Vec2(64., body_y), Vec2(8., 10.), body_height, 0.)

    try:
        grid = build_occlusion_grid([body], [source], width=128., height=128., beam_margin=20.)
        texture = renderer.upload(grid)
        _uniform(shader, "u_occlusion_grid", [grid.origin.x, grid.origin.y, float(grid.columns), float(grid.rows)])
        _uniform(shader, "u_occlusion_cell_size", [grid.cell_size])
        _integer(shader, "u_dynamic_shadows", 1)
        with texture_mode(target):
            rl.begin_shader_mode(shader)
            rl.set_shader_value_texture(shader, rl.get_shader_location(shader, "u_occlusion_tex"), texture)
            rl.draw_rectangle(0, 0, 2, 2, rl.WHITE)
            rl.end_shader_mode()
        projected, reference, _, _ = _pixel(target)
        # A tall body past the light must not shadow from beyond it.
        assert 0. < projected < 1. if shadowed else projected == 1.
        assert projected == pytest.approx(reference, abs=.08)
    finally:
        renderer.close()
        rl.unload_shader(shader)
        rl.unload_render_texture(target)


@pytest.mark.parametrize(("body_y", "lit"), [(20., "full"), (29., "partial"), (60., "dark")])
def test_body_does_not_shadow_a_light_inside_or_against_it(raylib_context, body_y: float, lit: str) -> None:
    # A muzzle flash pressed into a packed crowd: the creature it sits in must not cut its pool along a straight line.
    shader = _probe_shader("""
    void main() {
        float point = sourceVisibility(vec3(64., 100., 0.), vec3(64., 20., 20.), .5, vec2(1e19));
        float section = sectionVisibility(vec3(64., 100., 0.), vec3(64., 20., 20.), .5, vec2(1., 0.), 4., vec2(1e19));
        finalColor = vec4(point, section, 0., 1.);
    }
    """)
    target = load_float_render_texture(2, 2)
    renderer = ReflectionOcclusion()
    source = MaterialLight(Vec2(64., 20.), 200., (1., 1., 1.), height=20., source_width=.5, beam_profile=(16., 3.1, 1.05))
    body = BodyVolume(Vec2(64., body_y), Vec2(8., 8.), 40., 0.)
    try:
        grid = build_occlusion_grid([body], [source], width=128., height=128., beam_margin=4.)
        texture = renderer.upload(grid)
        _uniform(shader, "u_occlusion_grid", [grid.origin.x, grid.origin.y, float(grid.columns), float(grid.rows)])
        _uniform(shader, "u_occlusion_cell_size", [grid.cell_size])
        _integer(shader, "u_dynamic_shadows", 1)
        with texture_mode(target):
            rl.begin_shader_mode(shader)
            rl.set_shader_value_texture(shader, rl.get_shader_location(shader, "u_occlusion_tex"), texture)
            rl.draw_rectangle(0, 0, 2, 2, rl.WHITE)
            rl.end_shader_mode()
        for value in _pixel(target)[:2]:
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


def test_wide_section_keeps_blockers_its_transverse_taps_cross(raylib_context) -> None:
    # A section wider than the penumbra cap: its taps reach past the bodies' stored penumbra bound.
    shader = _probe_shader("""
    void main() {
        float section = sectionVisibility(vec3(100., 240., 0.), vec3(100., 100., 24.), 32., vec2(0., 1.), 10.,
                                          vec2(1e19));
        finalColor = vec4(section, 0., 0., 1.);
    }
    """)
    target = load_float_render_texture(2, 2)
    renderer = ReflectionOcclusion()
    source = MaterialLight(Vec2(100., 100.), 300., (1., 1., 1.), height=24., source_width=32., direction=Vec2(0., 1.),
                           length=20., beam_profile=(16., 3.1, 1.05))
    body = BodyVolume(Vec2(114., 135.), Vec2(4., 4.), 40., 0.)
    try:
        grid = build_occlusion_grid([body], [source], width=256., height=256., beam_margin=10.)
        texture = renderer.upload(grid)
        _uniform(shader, "u_occlusion_grid", [grid.origin.x, grid.origin.y, float(grid.columns), float(grid.rows)])
        _uniform(shader, "u_occlusion_cell_size", [grid.cell_size])
        _integer(shader, "u_dynamic_shadows", 1)
        with texture_mode(target):
            rl.begin_shader_mode(shader)
            rl.set_shader_value_texture(shader, rl.get_shader_location(shader, "u_occlusion_tex"), texture)
            rl.draw_rectangle(0, 0, 2, 2, rl.WHITE)
            rl.end_shader_mode()
        assert _pixel(target)[0] < .99
    finally:
        renderer.close()
        rl.unload_shader(shader)
        rl.unload_render_texture(target)


@pytest.mark.parametrize(("body_x", "body_y", "radius"), [(44., 20., 8.), (54., 20., 8.), (64., 20., 8.), (64., 32., 10.),
                                                          (60., 30., 12.)])
def test_section_spares_only_its_embedded_stretch(raylib_context, body_x: float, body_y: float, radius: float) -> None:
    # A section passing partly through a body: the embedded stretch is not shadowed by it, the rest still is, as the
    # section's point emitters sampled one by one see it.
    shader = _probe_shader("""
    void main() {
        vec3 receiver = vec3(64., 100., 0.), center = vec3(64., 20., 20.);
        float section = sectionVisibility(receiver, center, .5, vec2(1., 0.), 20., vec2(1e19));
        float reference = 0.;
        for (int i = 0; i < 64; i++) {
            float offset = ((float(i) + .5) / 64. * 2. - 1.) * 20.;
            reference += sourceVisibility(receiver, center + vec3(offset, 0., 0.), .5, vec2(1e19));
        }
        finalColor = vec4(section, reference / 64., 0., 1.);
    }
    """)
    target = load_float_render_texture(2, 2)
    renderer = ReflectionOcclusion()
    source = MaterialLight(Vec2(64., 20.), 200., (1., 1., 1.), height=20., source_width=.5, beam_profile=(16., 3.1, 1.05))
    body = BodyVolume(Vec2(body_x, body_y), Vec2(radius, radius), 40., 0.)
    try:
        grid = build_occlusion_grid([body], [source], width=128., height=128., beam_margin=20.)
        texture = renderer.upload(grid)
        _uniform(shader, "u_occlusion_grid", [grid.origin.x, grid.origin.y, float(grid.columns), float(grid.rows)])
        _uniform(shader, "u_occlusion_cell_size", [grid.cell_size])
        _integer(shader, "u_dynamic_shadows", 1)
        with texture_mode(target):
            rl.begin_shader_mode(shader)
            rl.set_shader_value_texture(shader, rl.get_shader_location(shader, "u_occlusion_tex"), texture)
            rl.draw_rectangle(0, 0, 2, 2, rl.WHITE)
            rl.end_shader_mode()
        section, reference = _pixel(target)[:2]
        assert section == pytest.approx(reference, abs=.1)
    finally:
        renderer.close()
        rl.unload_shader(shader)
        rl.unload_render_texture(target)


def test_section_visibility_fades_keeps_all_casters_and_resets_for_reflections(raylib_context) -> None:
    shader = _probe_shader("""
    uniform vec4 u_owner;
    void main() {
        vec3 receiver = vec3(64., 110., 0.), source = vec3(64., 20., 24.);
        float before = sourceVisibility(receiver, source, .5, u_owner.xy);
        float section = sectionVisibility(receiver, source, .5, vec2(1., 0.), 4., u_owner.xy);
        float after = sourceVisibility(receiver, source, .5, u_owner.xy);
        finalColor = vec4(section, before, after, 1.);
    }
    """)
    target = load_float_render_texture(2, 2)
    renderer = ReflectionOcclusion()
    source = MaterialLight(Vec2(64., 20.), 200., (1., 1., 1.), height=24., source_width=4.5, beam_profile=(16., 3.1, 1.05))
    body = BodyVolume(Vec2(64., 64.), Vec2(1.5, 1.5), 40., 0., owner=Vec2(64., 64.))

    def sample(bodies: Sequence[BodyVolume], *, shadows: bool = True, owner: Vec2 = Vec2(1e19, 1e19)):
        grid = build_occlusion_grid(bodies, [source], width=128., height=128., beam_margin=4.)
        texture = renderer.upload(grid)
        _uniform(shader, "u_occlusion_grid", [grid.origin.x, grid.origin.y, float(grid.columns), float(grid.rows)])
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
        assert 0. < blocked < .95
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


def test_bodies_blocking_different_stretches_of_a_beam_add_up(raylib_context) -> None:
    # Two bodies each hide one half of a long beam from the receiver: together they hide nearly all of it, where one
    # visibility per body, combined by its minimum, would still pass the half each leaves open.
    shader = _probe_shader("""
    void main() {
        float both = sectionVisibility(vec3(64., 120., 0.), vec3(64., 20., 24.), .5, vec2(1., 0.), 40., vec2(1e19));
        finalColor = vec4(both, 0., 0., 1.);
    }
    """)
    target = load_float_render_texture(2, 2)
    renderer = ReflectionOcclusion()
    source = MaterialLight(Vec2(64., 20.), 200., (1., 1., 1.), height=24., source_width=.5, direction=Vec2(1., 0.),
                           length=80., beam_profile=(16., 3.1, 1.05))
    halves = [BodyVolume(Vec2(x, 70.), Vec2(20., 8.), 30., 0.) for x in (44., 84.)]

    def visibility(bodies: Sequence[BodyVolume]) -> float:
        grid = build_occlusion_grid(bodies, [source], width=128., height=160., beam_margin=40.)
        texture = renderer.upload(grid)
        _uniform(shader, "u_occlusion_grid", [grid.origin.x, grid.origin.y, float(grid.columns), float(grid.rows)])
        _uniform(shader, "u_occlusion_cell_size", [grid.cell_size])
        _integer(shader, "u_dynamic_shadows", 1)
        with texture_mode(target):
            rl.begin_shader_mode(shader)
            rl.set_shader_value_texture(shader, rl.get_shader_location(shader, "u_occlusion_tex"), texture)
            rl.draw_rectangle(0, 0, 2, 2, rl.WHITE)
            rl.end_shader_mode()
        return _pixel(target)[0]

    try:
        left, right, both = visibility(halves[:1]), visibility(halves[1:]), visibility(halves)
        assert .3 < left < .7 and .3 < right < .7
        assert both < .15
        assert both == pytest.approx(left + right - 1., abs=.1)
    finally:
        renderer.close()
        rl.unload_shader(shader)
        rl.unload_render_texture(target)


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
