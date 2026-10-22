from __future__ import annotations

from typing import Any, cast
from unittest.mock import patch

import msgspec
import numpy as np
import pytest

from crimson.projectiles.types import Projectile
from crimson.projectiles.types import ProjectileTemplateId as PT
from crimson.render.rtx import beam
from crimson.render.rtx.mode import RtxRenderMode
from crimson.render.world import projectiles
from grim.edr import load_float_render_texture
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.texture_mode import texture_mode
from tests.render.test_projectile_render import _place, _render_ctx
from tests.support.factories import make_creature_state


@pytest.mark.parametrize("preserve_bugs", [False, True])
def test_mixed_projectile_batch_preserves_hdr_pixels_and_order(raylib_context, mocker, preserve_bugs):
    # Interleave overlapping beams, atlas sprites, different stamp spacings,
    # faded ion arcs, zero-length heads, and a following non-beam draw.
    image = rl.gen_image_checked(64, 64, 8, 8, rl.Color(40, 80, 120, 90), rl.Color(80, 30, 20, 170))
    texture = rl.load_texture_from_image(image)
    rl.unload_image(image)
    target = load_float_render_texture(128, 128, pixel_format=rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32)
    mocker.patch.object(beam, "_BEAM_FAST_STAMPED_SHADER_TRIED", False)
    mocker.patch.object(beam, "_BEAM_FAST_STAMPED_SHADER", None)

    class Resources:
        def texture(self, _texture_id):
            return texture

    ctx = _render_ctx(rtx_mode=RtxRenderMode.RTX)
    ctx = msgspec.structs.replace(ctx, frame=msgspec.structs.replace(ctx.frame, resources=cast(Any, Resources())))
    ctx.frame.state.preserve_bugs = preserve_bugs
    ctx.frame.creatures.entries[0] = make_creature_state(pos=Vec2(90, 60), hp=100, size=20)
    kinds = [
        PT.FIRE_BULLETS,
        PT.ION_MINIGUN,
        PT.PULSE_GUN,
        PT.ION_CANNON,
        PT.ION_RIFLE,
        PT.BLADE_GUN,
        PT.FIRE_BULLETS,
        PT.SPLITTER_GUN,
        PT.ION_RIFLE,
        PT.PULSE_GUN,
    ]
    _place(
        ctx,
        [
            Projectile(
                type_id=kind,
                origin=Vec2(18 + i, 20 + i * 3),
                pos=Vec2(65, 55 + i),
                life_timer=0.2 if i == 4 else 0.4,
                angle=0.1 * i,
            )
            for i, kind in enumerate(kinds)
        ],
    )
    ctx.frame.state.projectiles.entries[8].origin = ctx.frame.state.projectiles.entries[8].pos
    body, head = beam.draw_beam_fast_stamped_body, beam.draw_beam_fast_stamped_head

    def unbatched_body(**kwargs):
        kwargs.pop("batch")
        return body(**kwargs)

    def unbatched_head(**kwargs):
        kwargs.pop("batch")
        return head(**kwargs)

    def render():
        with texture_mode(target):
            rl.clear_background(rl.BLACK)
            state = projectiles._projectile_sprite_pass(ctx, alpha=0.8)
            # Detect a beam shader leaking past the pass boundary.
            rl.draw_rectangle(0, 110, 128, 18, rl.Color(25, 50, 75, 255))
        image = rl.load_image_from_texture(target.texture)
        try:
            rl.image_format(image, rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R32G32B32A32)
            pixels = np.frombuffer(rl.ffi.buffer(image.data, 128 * 128 * 16), dtype=np.float32).copy()
            return state, pixels
        finally:
            rl.unload_image(image)

    try:
        with (
            patch.object(projectiles, "draw_beam_fast_stamped_body", unbatched_body),
            patch.object(projectiles, "draw_beam_fast_stamped_head", unbatched_head),
        ):
            reference_state, reference = render()
        state, actual = render()
        assert state == reference_state
        assert np.isfinite(actual).all()
        assert actual.max() > 1.0  # Exercise unclamped additive HDR output.
        np.testing.assert_array_equal(actual, reference)
    finally:
        if beam._BEAM_FAST_STAMPED_SHADER is not None:
            rl.unload_shader(beam._BEAM_FAST_STAMPED_SHADER.shader)
        rl.unload_render_texture(target)
        rl.unload_texture(texture)


def test_batch_flushes_before_uniform_changes_and_restarts_after_end(mocker):
    shader = cast(Any, mocker.Mock())
    calls = mocker.Mock()
    for name in ("begin_shader_mode", "end_shader_mode", "rl_draw_render_batch_active"):
        calls.attach_mock(mocker.patch.object(rl, name), name)
    calls.attach_mock(mocker.patch.object(beam, "_apply_virtual_beam_uniforms"), "initialize")
    calls.attach_mock(mocker.patch.object(beam, "_set_shader_float"), "step")
    batch = beam.BeamBatch()
    batch.prepare(shader, 0.2)
    batch.prepare(shader, None)
    batch.prepare(shader, 0.2 + 1e-16)
    assert [c[0] for c in calls.mock_calls] == ["begin_shader_mode", "initialize"]
    batch.prepare(shader, 0.3)
    batch.end()
    batch.end()
    batch.prepare(shader, None)
    batch.end()
    assert [c[0] for c in calls.mock_calls] == [
        "begin_shader_mode",
        "initialize",
        "rl_draw_render_batch_active",
        "step",
        "end_shader_mode",
        "begin_shader_mode",
        "initialize",
        "end_shader_mode",
    ]
