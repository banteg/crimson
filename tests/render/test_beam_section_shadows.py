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
from crimson.render.rtx.reflection_occlusion import BodyVolume, ReflectionOcclusion, build_occlusion_grid
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


@pytest.mark.parametrize("body_height", [12., 40.])
def test_projected_visibility_matches_sampled_reference(raylib_context, body_height: float) -> None:
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
    source = MaterialLight(Vec2(64., 20.), 200., (1., 1., 1.), height=24., source_width=4.5)
    body = BodyVolume(Vec2(64., 60.), Vec2(8., 10.), body_height, 0.)

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
        projected, reference, _, _ = _pixel(target)
        assert 0. < projected < 1.
        assert projected == pytest.approx(reference, abs=.08)
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
    source = MaterialLight(Vec2(64., 20.), 200., (1., 1., 1.), height=24., source_width=4.5)
    body = BodyVolume(Vec2(64., 64.), Vec2(1.5, 1.5), 40., 0., owner=Vec2(64., 64.))

    def sample(bodies: Sequence[BodyVolume], *, shadows: bool = True, owner: Vec2 = Vec2(1e19, 1e19)):
        grid = build_occlusion_grid(bodies, [source], width=128., height=128.)
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
        assert sample([half] * 70) == pytest.approx(sample([half]), abs=.002)
        # A late stronger caster must not disappear behind an arbitrary budget.
        assert sample([half] * 70 + [body]) == pytest.approx(blocked, abs=.002)
        assert sample([body] + [half] * 70) == pytest.approx(blocked, abs=.002)
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
