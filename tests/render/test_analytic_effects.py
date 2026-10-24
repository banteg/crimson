from __future__ import annotations

import numpy as np
import pytest

from crimson.render.rtx import effects
from grim.color import RGBA
from grim.edr import load_float_render_texture
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.shaders import AlphaTestShader
from grim.texture_mode import texture_mode


@pytest.fixture
def effect_shader(raylib_context, mocker):
    mocker.patch.object(effects, "_shader", None)
    yield
    if effects._shader is not None:
        rl.unload_shader(effects._shader.shader)


def _render(draw):
    target = load_float_render_texture(128, 128, pixel_format=rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32)
    try:
        with texture_mode(target):
            rl.clear_background(rl.BLANK)
            rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
            draw()
            rl.end_blend_mode()
        image = rl.load_image_from_texture(target.texture)
        try:
            rl.image_format(image, rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32)
            return (
                np.frombuffer(rl.ffi.buffer(image.data, 128 * 128 * 16), dtype=np.float32).reshape(128, 128, 4).copy()
            )
        finally:
            rl.unload_image(image)
    finally:
        rl.unload_render_texture(target)


@pytest.mark.parametrize("shape", [effects.EffectShape.GLOW, effects.EffectShape.AURA, effects.EffectShape.RING])
def test_sprite_profiles_fade_and_leave_the_quad_edge_clear(effect_shader, shape):
    def render(alpha):
        return _render(
            lambda: effects.draw_sprite(shape, center=Vec2(64, 64), width=80, height=60, color=RGBA(a=alpha)),
        )

    bright, faded, invisible = render(1.0), render(0.2), render(0.005)
    assert np.isfinite(bright).all()
    assert bright[..., :3].max() > 0.1
    assert 0 < faded[..., :3].sum() < bright[..., :3].sum()
    assert invisible[..., :3].max() == 0
    assert bright[:25, :, :3].max() == 0
    assert bright[:, :20, :3].max() == 0


def test_plasma_integral_matches_dense_actual_glow_draws(effect_shader):
    actual = _render(
        lambda: effects.draw_plasma(
            center=Vec2(90, 64),
            tail_axis=Vec2(-1, 0),
            segments=18,
            step=1.5,
            tail_radius=8,
            head_radius=0,
            head_alpha=0,
            aura_radius=0,
            aura_alpha=0,
            alpha=1.0,
            color=(1.0, 1.0, 1.0),
        ),
    )
    samples = 160

    def dense_reference():
        for i in range(samples):
            x = 90 - 26.25 + (i + 0.5) * 27 / samples
            effects.draw_sprite(effects.EffectShape.GLOW, center=Vec2(x, 64), width=16, height=16, color=RGBA(a=0.4))

    expected = _render(dense_reference)[..., :3] * (18 / samples)
    error = actual[..., :3] - expected
    assert np.isfinite(actual).all()
    assert actual[..., :3].max() > 1.0  # Do not clip overlapping layers before tonemapping.
    assert np.sqrt(np.mean(error**2)) < 0.002
    assert np.abs(error).max() < 0.008


def test_arc_cap_setting_changes_only_the_strip_ends(effect_shader):
    def draw(capped):
        return _render(
            lambda: effects.draw_ion_arc(
                start=Vec2(40, 64), end=Vec2(88, 64), effect_scale=1.0, alpha=0.5, capped=capped,
            ),
        )

    capped, native_cut = draw(True), draw(False)
    np.testing.assert_array_equal(capped[:, 42:86], native_cut[:, 42:86])
    assert capped[..., :3].sum() > native_cut[..., :3].sum()
    assert np.isfinite(capped).all()


def test_analytic_draw_restores_enclosing_alpha_test(effect_shader):
    image = rl.gen_image_color(1, 1, rl.Color(255, 255, 255, 3))
    texture = rl.load_texture_from_image(image)
    rl.unload_image(image)
    test = AlphaTestShader()
    try:

        def draw():
            with test.scope():
                effects.draw_sprite(effects.EffectShape.GLOW, center=Vec2(32, 64), width=20, height=20, color=RGBA())
                rl.draw_texture_ex(texture, rl.Vector2(80, 40), 0.0, 20.0, rl.WHITE)

        pixels = _render(draw)
        assert pixels[:, 80:100, :3].max() == 0
        assert pixels[..., :3].max() > 0
    finally:
        test.close()
        rl.unload_texture(texture)
