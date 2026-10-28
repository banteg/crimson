from __future__ import annotations

import numpy as np
import pytest

from crimson.effects import EffectEntry
from crimson.effects_atlas import EffectId
from crimson.render.rtx import effects
from crimson.render.rtx.mode import RtxRenderMode
from crimson.render.world import effects as world_effects
from grim.color import RGBA
from grim.edr import load_float_render_texture
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.shaders import AlphaTestShader
from grim.texture_mode import texture_mode
from tests.render.test_projectile_render import _render_ctx


@pytest.mark.parametrize("flags", [0x40, 0x19])
@pytest.mark.parametrize("effect_id", [EffectId.GLOW, EffectId.AURA, EffectId.BURST])
def test_emissive_profile_is_used_only_for_additive_entries(mocker, flags, effect_id):
    ctx = _render_ctx(rtx_mode=RtxRenderMode.RTX)
    ctx.frame.state.effects.entries[0] = EffectEntry(
        effect_id=effect_id,
        pos=Vec2(40, 40),
        flags=flags,
        half_width=20.0,
        half_height=30.0,
        scale=1.0,
    )
    sprite = mocker.patch.object(world_effects, "draw_sprite")
    texture = mocker.patch.object(rl, "draw_texture_pro")
    mocker.patch.object(rl, "begin_blend_mode")
    mocker.patch.object(rl, "end_blend_mode")
    world_effects.draw_effect_pool(ctx, camera=Vec2(), view_scale=Vec2(1, 1))
    assert sprite.call_count == (flags != 0x40)
    assert texture.call_count == (flags == 0x40)


@pytest.mark.parametrize("mode", [RtxRenderMode.RTX, RtxRenderMode.CLASSIC])
@pytest.mark.parametrize("flags", [0x19, 0x1D, 0x59, 0x5D])
def test_bonus_glints_keep_their_texture_while_explosion_flashes_are_radial(mocker, mode, flags):
    ctx = _render_ctx(rtx_mode=mode)
    ctx.frame.state.effects.entries[0] = EffectEntry(
        effect_id=EffectId.BURST, pos=Vec2(40, 40), flags=flags,
        half_width=32, half_height=32, scale=1, rotation=.7, color=RGBA(.4, .5, 1, .5),
    )
    sprite = mocker.patch.object(world_effects, "draw_sprite")
    texture = mocker.patch.object(rl, "draw_texture_pro")
    mocker.patch.object(rl, "begin_blend_mode")
    mocker.patch.object(rl, "end_blend_mode")
    world_effects.draw_effect_pool(ctx, camera=Vec2(), view_scale=Vec2(1, 1))
    analytic = mode is RtxRenderMode.RTX and flags == 0x19
    assert sprite.call_count == analytic
    assert texture.call_count == (not analytic)
    if not analytic:
        assert texture.call_args.args[4] == pytest.approx(.7 * 180 / np.pi)
        assert texture.call_args.args[5].b == 255


@pytest.fixture
def effect_shader(raylib_context, mocker):
    mocker.patch.object(effects, "_shader", None)
    yield
    if effects._shader is not None:
        rl.unload_shader(effects._shader.shader)


def _render(draw, *, linear=True):
    target = load_float_render_texture(128, 128, pixel_format=rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32)
    try:
        with texture_mode(target, linear=linear):
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


@pytest.mark.parametrize("linear", [False, True])
@pytest.mark.parametrize("shape", [effects.EffectShape.GLOW, effects.EffectShape.AURA, effects.EffectShape.RING, effects.EffectShape.BURST, effects.EffectShape.PULSE])
def test_sprite_profiles_fade_and_leave_the_quad_edge_clear(effect_shader, shape, linear):
    def render(alpha):
        return _render(
            lambda: effects.draw_sprite(shape, center=Vec2(64, 64), width=80, height=60, color=RGBA(a=alpha)),
            linear=linear,
        )

    bright, faded, invisible = render(1.0), render(0.2), render(0.005)
    assert np.isfinite(bright).all()
    assert bright[..., :3].max() > 0.1
    assert 0 < faded[..., :3].sum() < bright[..., :3].sum()
    # Even one byte of emission remains light; zero is still exactly invisible.
    assert 0 < invisible[..., :3].sum() < faded[..., :3].sum()
    np.testing.assert_allclose(invisible[..., :3] * 255, bright[..., :3], atol=2e-6)
    assert render(0.0)[..., :3].max() == 0
    assert bright[:25, :, :3].max() == 0
    assert bright[:, :20, :3].max() == 0


@pytest.mark.parametrize("linear", [False, True])
def test_plasma_integral_matches_dense_actual_glow_draws(effect_shader, linear):
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
        linear=linear,
    )
    samples = 160

    def dense_reference():
        for i in range(samples):
            x = 90 - 26.25 + (i + 0.5) * 27 / samples
            effects.draw_sprite(effects.EffectShape.GLOW, center=Vec2(x, 64), width=16, height=16, color=RGBA(a=0.4))

    expected = _render(dense_reference, linear=linear)[..., :3] * (18 / samples)
    error = actual[..., :3] - expected
    assert np.isfinite(actual).all()
    assert actual[..., :3].max() > 1.0  # Do not clip overlapping layers before tonemapping.
    assert np.sqrt(np.mean(error**2)) < 0.002
    assert np.abs(error).max() < 0.008


def test_arc_cap_setting_changes_only_the_strip_ends(effect_shader):
    def draw(capped):
        return _render(
            lambda: effects.draw_ion_arc(
                start=Vec2(40, 64),
                end=Vec2(88, 64),
                effect_scale=1.0,
                alpha=0.5,
                capped=capped,
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


@pytest.mark.parametrize("linear", [False, True])
@pytest.mark.parametrize("shape", [effects.EffectShape.GLOW, effects.EffectShape.AURA, effects.EffectShape.RING, effects.EffectShape.BURST, effects.EffectShape.PULSE])
def test_sprite_batch_preserves_pixels_and_binds_shader_once(effect_shader, mocker, shape, linear):
    def draw(batched):
        with effects.sprite_batch() as batch:
            for i in range(12):
                effects.draw_sprite(
                    shape,
                    center=Vec2(40 + i * 3, 60),
                    width=50.0,
                    height=40.0,
                    rotation=i * 0.03,
                    color=RGBA(0.3 + i * 0.04, 0.8 - i * 0.02, 0.5, 0.2 + i * 0.04),
                    batch=batch if batched else None,
                )

    reference = _render(lambda: draw(False), linear=linear)
    binds = mocker.spy(rl, "begin_shader_mode")
    actual = _render(lambda: draw(True), linear=linear)
    np.testing.assert_array_equal(actual, reference)
    assert binds.call_count == 1


@pytest.mark.parametrize("shape", [effects.EffectShape.AURA, effects.EffectShape.ION_ARC, effects.EffectShape.PULSE])
def test_linear_effects_decode_hue_but_preserve_faint_emission(effect_shader, shape):
    def draw(alpha):
        if shape is effects.EffectShape.ION_ARC:
            effects.draw_ion_arc(start=Vec2(24, 64), end=Vec2(104, 64), effect_scale=1, alpha=alpha, capped=True)
        else:
            effects.draw_sprite(shape, center=Vec2(64, 64), width=80, height=80, color=RGBA(.5, .6, 1, alpha))

    bright = _render(lambda: draw(1.0))
    faint = _render(lambda: draw(3 / 255))
    np.testing.assert_allclose(faint[..., :3] * 85, bright[..., :3], atol=2e-6)
    assert bright[..., 2].max() > .1
    if shape is not effects.EffectShape.PULSE:  # Pulse adds a deliberately whiter front edge.
        np.testing.assert_allclose(bright[..., 0], bright[..., 2] * (128 / 255) ** 2.2, atol=2e-6)
        np.testing.assert_allclose(bright[..., 1], bright[..., 2] * .6 ** 2.2, atol=2e-6)


@pytest.mark.parametrize("part", ["tail", "head", "aura"])
def test_plasma_components_survive_below_the_art_cutoff_in_linear_light(effect_shader, part):
    def render(alpha):
        return _render(lambda: effects.draw_plasma(
            center=Vec2(90, 64), tail_axis=Vec2(-1, 0),
            segments=8 if part == "tail" else 0, step=2, tail_radius=8,
            head_radius=16 if part == "head" else 0, head_alpha=.4,
            aura_radius=50 if part == "aura" else 0, aura_alpha=.4,
            alpha=alpha, color=(.3, 1, .3),
        ))

    bright, faint, zero = render(1), render(3 / 102), render(0)
    assert faint[..., :3].max() > 0
    np.testing.assert_allclose(faint[..., :3] * 34, bright[..., :3], atol=2e-6)
    assert zero[..., :3].max() == 0
