from __future__ import annotations

import math
import struct
from itertools import pairwise

import msgspec
import pytest

from crimson.render.rtx.continuous_beam import (
    CELLS,
    KNOTS,
    ContinuousBeam,
    configure,
    experiment,
    moments,
    pack_candidates,
)
from crimson.render.rtx.continuous_beam_shaders import CONTINUOUS_BEAM_GLSL
from crimson.render.rtx.material_lights import MaterialLight
from crimson.render.rtx.materials import _integer, _shader, _uniform
from crimson.render.rtx.reflection_occlusion import BodyVolume
from grim.edr import load_float_render_texture
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.texture_mode import texture_mode


def light() -> MaterialLight:
    return MaterialLight(Vec2(128, 40), 10000, (1, 1, 1), height=24, direction=Vec2(1, 0), length=256,
                         beam_profile=(56., 9., 1.05), beam_ion=True)


def test_moments_normalize_and_rebase_for_each_weapon_and_length() -> None:
    for length in (0., .001, 16., 193.7, 256.):
        for profile in ((16.8, 3.255, 1.05), (35.2, 6.82, 1.05), (56., 9., 1.05), (12.8, 2.48, 1.35)):
            values, pad = moments(length, *profile)
            assert pad > 0 and len(values) == CELLS * KNOTS * 4
            total = 0.
            for cell in range(CELLS):
                records = [values[(cell * KNOTS + j) * 4:][:3] for j in range(KNOTS)]
                assert records[0] == (0., 0., 0.)
                for a, b in pairwise(records):
                    assert all(y >= x for x, y in zip(a, b, strict=True))
                mass, first, second = records[-1]
                assert 0 <= second <= first <= mass
                if mass > 0:
                    assert second / mass >= (first / mass) ** 2 - 1e-12
                total += mass
            assert total == pytest.approx(1.)
    assert moments.cache_info().maxsize == 64


def test_candidate_packing_never_drops_dense_or_translucent_bodies() -> None:
    bodies = [BodyVolume(Vec2(100, 90), Vec2(12, 9), 50, 0, opacity=.5) for _ in range(384)]
    grid = pack_candidates(bodies, [light()], width=256, height=256)
    assert grid.body_count == 384
    assert max(grid.values[i * 4 + 1] for i in range(grid.rows * grid.columns)) == 384
    off, count = grid.values[:2]
    assert len({grid.values[(int(off) + j) * 4] for j in range(int(count))}) == count


def test_console_validation_is_atomic(monkeypatch) -> None:
    monkeypatch.setattr(experiment, "enabled", False)
    monkeypatch.setattr(experiment, "ion_gain", 4.)
    monkeypatch.setattr(experiment, "ambient_dip", .25)
    for args in (("on", "nan"), ("on", "9"), ("on", "4", "-.1"), ("on", "4", ".7")):
        with pytest.raises(ValueError):
            configure(args)
        assert not experiment.enabled
    configure(("on", "3", ".2"))
    assert (experiment.enabled, experiment.ion_gain, experiment.ambient_dip) == (True, 3, .2)


def test_native_continuous_visibility_fades_overlap_and_keeps_overflow(raylib_context) -> None:
    # Constant radiance kernel isolates visibility. Independent dense hard rays
    # below integrate the same energy texture without using interval roots.
    source = light()
    helper = CONTINUOUS_BEAM_GLSL.replace(
        "return direct_albedo*sp_col.rgb*(response.x*atten*angular*relief);", "return vec3(1.);")
    shader = _shader("#version 330\n#define MAX_SPEC_LIGHTS 32\nuniform int u_dynamic_shadows;\nout vec4 finalColor;\n" + helper + """
    void main() {
        vec3 unshadowed;
        vec3 value=continuousLight(0,vec4(1.,0.,1.,256.),vec2(100.,150.),vec3(0.,0.,1.),vec3(0.),vec3(1.),vec3(0.),vec3(1.),0.,vec4(128.,40.,10000.,24.),vec4(1.),vec4(1.),1.,unshadowed);
        finalColor=vec4(value,1.);
    }
    """)
    target = load_float_render_texture(2, 2)
    renderer = ContinuousBeam()
    body = BodyVolume(Vec2(100, 100), Vec2(13, 8), 12., .2)

    def draw(bodies, shadows=True):
        infos = renderer.prepare(bodies, [source], width=256, height=256)
        _integer(shader, "u_dynamic_shadows", int(shadows))
        _uniform(shader, "u_beam_tuning", [1., 0.])
        _uniform(shader, "u_beam_grid", [2., 2.])
        _uniform(shader, "u_beam_info[0]", list(infos[0]))
        assert renderer.moment_texture is not None and renderer.candidates.texture is not None
        with texture_mode(target):
            rl.begin_shader_mode(shader)
            rl.set_shader_value_texture(shader, rl.get_shader_location(shader, "u_moments"), renderer.moment_texture)
            rl.set_shader_value_texture(shader, rl.get_shader_location(shader, "u_beam_candidates"), renderer.candidates.texture)
            rl.draw_rectangle(0, 0, 2, 2, rl.WHITE)
            rl.end_shader_mode()
        image = rl.load_image_from_texture(target.texture)
        try:
            rl.image_format(image, rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32)
            return struct.unpack("f", bytes(rl.ffi.buffer(image.data, 4)))[0]
        finally:
            rl.unload_image(image)

    try:
        clear = draw([])
        blocked = draw([body])
        half = msgspec.structs.replace(body, opacity=.5)
        assert clear == pytest.approx(1., abs=.002)
        assert 0 < blocked < .95
        assert draw([half]) == pytest.approx((clear + blocked) / 2, abs=.002)
        assert draw([half, half]) == pytest.approx(draw([half]), abs=.002)
        assert draw([half] * 70) == pytest.approx(draw([half]), abs=.002)
        # Overflow remains sticky even when a late opaque interval would merge
        # everything. Both orders must process all originals, not a stale cache.
        covering = BodyVolume(Vec2(100, 150), Vec2(30, 30), 12., 0)
        assert draw([half] * 70 + [covering]) == pytest.approx(0., abs=.002)
        assert draw([covering] + [half] * 70) == pytest.approx(0., abs=.002)
        partial = msgspec.structs.replace(covering, opacity=.8)
        assert draw([half] * 70 + [partial]) == pytest.approx(.2, abs=.002)
        assert draw([partial] + [half] * 70) == pytest.approx(.2, abs=.002)
        assert draw([body], shadows=False) == pytest.approx(clear, abs=.002)
        assert draw([msgspec.structs.replace(body, opacity=0.)]) == pytest.approx(clear, abs=.002)

        assert source.beam_profile is not None
        values, pad = moments(source.length, *source.beam_profile)
        visible = 0.
        for cell in range(CELLS):
            for j in range(KNOTS - 1):
                mass = values[(cell*KNOTS+j+1)*4]-values[(cell*KNOTS+j)*4]
                t = (cell+(j+.5)/(KNOTS-1))/CELLS
                sx = -pad+t*(256+2*pad)
                q = [100-body.pos.x,150-body.pos.y,-body.height*.4]
                ray = [sx-100,40-150,24]
                c,s = math.cos(body.angle),math.sin(body.angle)
                q[:2] = [c*q[0]+s*q[1],-s*q[0]+c*q[1]]
                ray[:2] = [c*ray[0]+s*ray[1],-s*ray[0]+c*ray[1]]
                radii = (body.radii.x,body.radii.y,body.height*.6)
                q = [v/r for v,r in zip(q,radii,strict=True)]
                ray = [v/r for v,r in zip(ray,radii,strict=True)]
                hit_t = min(1.,max(0.,-sum(a*b for a,b in zip(q,ray,strict=True))/sum(v*v for v in ray)))
                if sum((a+hit_t*b)**2 for a,b in zip(q,ray,strict=True))>1:
                    visible += mass
        assert blocked == pytest.approx(visible, abs=.008)
    finally:
        renderer.close()
        rl.unload_shader(shader)
        rl.unload_render_texture(target)
