from __future__ import annotations

import struct

import pytest

from crimson.game.loop_view import GameLoopView
from crimson.render.rtx.hdr import HDR_PIXEL_FORMAT, HdrRenderer, load_float_target
from grim import edr
from grim.geom import Vec2
from grim.raylib_api import ffi, rl
from grim.shaders import AlphaTestShader
from grim.texture_mode import texture_mode


def _rgb(image: rl.Image, x: int, y: int) -> tuple[int, int, int]:
    color = rl.get_image_color(image, x, y)
    return color.r, color.g, color.b


def test_alpha_test_cutoff_and_default_shader_restoration(raylib_context) -> None:
    alpha_test = AlphaTestShader()
    target = rl.load_render_texture(80, 16)
    try:
        # Run twice to exercise release and lazy reload in the same GL context.
        for _ in range(2):
            rl.begin_texture_mode(target)
            try:
                rl.clear_background(rl.BLACK)
                with alpha_test.scope():
                    for i, alpha in enumerate((3, 4, 5, 255)):
                        rl.draw_rectangle(i * 16, 0, 16, 16, rl.Color(255, 0, 0, alpha))
                rl.draw_rectangle(64, 0, 16, 16, rl.Color(255, 0, 0, 3))
            finally:
                rl.end_texture_mode()
            image = rl.load_image_from_texture(target.texture)
            try:
                assert [_rgb(image, x, 8)[0] for x in (8, 24, 40, 56, 72)] == [0, 4, 5, 255, 3]
            finally:
                rl.unload_image(image)
            alpha_test.close()
    finally:
        alpha_test.close()
        rl.unload_render_texture(target)


def test_alpha_test_scope_ends_after_an_error_and_keeps_its_handle_until_close(raylib_context) -> None:
    alpha_test = AlphaTestShader()
    target = rl.load_render_texture(16, 16)
    try:
        with pytest.raises(RuntimeError, match="draw failed"), alpha_test.scope():
            raise RuntimeError("draw failed")
        shader = alpha_test.shader
        assert shader is not None
        rl.begin_texture_mode(target)
        try:
            rl.clear_background(rl.BLACK)
            # Still bound, the shader would discard this alpha-3 draw.
            rl.draw_rectangle(0, 0, 16, 16, rl.Color(255, 0, 0, 3))
            with alpha_test.scope():
                pass
        finally:
            rl.end_texture_mode()
        assert alpha_test.shader is shader
        image = rl.load_image_from_texture(target.texture)
        try:
            assert _rgb(image, 8, 8)[0] == 3
        finally:
            rl.unload_image(image)

        alpha_test.close()
        assert alpha_test.shader is None
        alpha_test.close()
        with alpha_test.scope():
            pass
        assert alpha_test.shader is not None
        assert alpha_test.shader is not shader
    finally:
        alpha_test.close()
        rl.unload_render_texture(target)


@pytest.mark.parametrize(("gain", "debug_map"), [(1.0, False), (1.5, False), (1.5, True)])
def test_gamma_covers_inner_shader_and_later_drawing_at_display_resolution(
    raylib_context,
    make_game_state,
    mocker,
    gain: float,
    debug_map: bool,
) -> None:
    view = GameLoopView(make_game_state())
    view.state.gamma_ramp = gain
    if debug_map:
        from crimson.screens.stack import ScreenEntry

        screen = mocker.Mock(rtx_debug_map_active=True)
        view.state.screens.push(ScreenEntry(screen))
    display_gain = 1.0 if debug_map else gain
    alpha_test = AlphaTestShader()
    screen_w, screen_h = rl.get_screen_width(), rl.get_screen_height()

    def draw_scene() -> None:
        rl.clear_background(rl.Color(20, 30, 40, 255))
        with alpha_test.scope():
            rl.draw_rectangle(0, 0, screen_w // 2, screen_h // 2, rl.Color(60, 80, 100, 255))
        rl.draw_rectangle(screen_w // 2, screen_h // 2, screen_w // 2, screen_h // 2, rl.Color(100, 120, 140, 255))

    mocker.patch.object(view, "_draw_scene_layers", side_effect=draw_scene)
    try:
        rl.begin_drawing()
        try:
            view.draw()
            rl.rl_draw_render_batch_active()
            image = rl.load_image_from_screen()
            try:
                assert (image.width, image.height) == (rl.get_render_width(), rl.get_render_height())
                if display_gain != 1.0:
                    assert view._gamma_target is not None
                    assert (view._gamma_target.texture.width, view._gamma_target.texture.height) == (
                        image.width,
                        image.height,
                    )
                for x, y, rgb in (
                    (image.width // 4, image.height // 4, (60, 80, 100)),
                    (image.width * 3 // 4, image.height // 4, (20, 30, 40)),
                    (image.width // 4, image.height * 3 // 4, (20, 30, 40)),
                    (image.width * 3 // 4, image.height * 3 // 4, (100, 120, 140)),
                ):
                    assert _rgb(image, x, y) == pytest.approx(tuple(c * display_gain for c in rgb), abs=1)
            finally:
                rl.unload_image(image)
        finally:
            rl.end_drawing()
    finally:
        alpha_test.close()
        view._close_gamma_resources()


def test_hdr_scope_preserves_additive_hue_and_drifts_hot_core_to_white(raylib_context) -> None:
    hdr = HdrRenderer()
    target = rl.load_render_texture(64, 16)
    try:
        for _ in range(2):
            with texture_mode(target):
                rl.clear_background(rl.BLACK)
                with hdr.scope(out_size=Vec2(64.0, 16.0)):
                    # Region 0 (x=0..15): below knee (0.85) -> exact identity.
                    rl.draw_rectangle(0, 0, 16, 16, rl.Color(120, 160, 200, 255))
                    rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
                    try:
                        # Region 1 (x=16..31): 2x orange additive -> in 8-bit R & G both saturate (255, 255, 50);
                        # in RGBA16F + hue-preserving shoulder, R stays strictly above G.
                        for _ in range(2):
                            rl.draw_rectangle(16, 0, 16, 16, rl.Color(255, 153, 25, 255))
                        # Region 2 (x=32..47): 3x orange additive -> hotter core drifts further toward white.
                        for _ in range(3):
                            rl.draw_rectangle(32, 0, 16, 16, rl.Color(255, 153, 25, 255))
                        # Region 3 (x=48..63): 5x orange additive -> maximum white drift (heat=0.6).
                        for _ in range(5):
                            rl.draw_rectangle(48, 0, 16, 16, rl.Color(255, 153, 25, 255))
                    finally:
                        rl.end_blend_mode()
            assert hdr.target is not None
            assert hdr.shader is not None
            image = rl.load_image_from_texture(target.texture)
            try:
                below_knee = _rgb(image, 8, 8)
                warm_2x = _rgb(image, 24, 8)
                hot_3x = _rgb(image, 40, 8)
                core_5x = _rgb(image, 56, 8)

                assert below_knee == pytest.approx((120, 160, 200), abs=1)
                assert warm_2x == pytest.approx((255, 173, 71), abs=2)
                assert hot_3x == pytest.approx((255, 194, 117), abs=2)
                assert core_5x == pytest.approx((255, 214, 163), abs=2)
                assert warm_2x[0] > warm_2x[1] > warm_2x[2]
                assert warm_2x[1] < hot_3x[1] < core_5x[1]
                assert warm_2x[2] < hot_3x[2] < core_5x[2]
            finally:
                rl.unload_image(image)
            hdr.close()
            assert hdr.target is None
            assert hdr.shader is None
    finally:
        hdr.close()
        rl.unload_render_texture(target)


def test_hdr_scope_outputs_extended_srgb_above_one_on_edr_float_target(raylib_context, mocker) -> None:
    mocker.patch.object(edr, "_edr_active", True)
    mocker.patch.object(edr, "_headroom", 5.0)
    hdr = HdrRenderer()
    target = load_float_target(64, 16)
    try:
        with texture_mode(target):
            rl.clear_background(rl.BLACK)
            with hdr.scope(out_size=Vec2(64.0, 16.0)):
                # Region 0 (x=0..15): below knee (0.85) stays in SDR (< 0.85).
                rl.draw_rectangle(0, 0, 16, 16, rl.Color(120, 160, 200, 255))
                rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
                try:
                    # Region 1 (x=16..31): single Ion ring/arc (0.5, 0.6, 1.0) stays below reference white.
                    rl.draw_rectangle(16, 0, 16, 16, rl.Color(128, 153, 255, 255))
                    # Region 2 (x=32..47): 2x Ion beam spine reaches extended output.
                    for _ in range(2):
                        rl.draw_rectangle(32, 0, 16, 16, rl.Color(128, 153, 255, 255))
                    # Region 3 (x=48..63): 4x Ion head/core rolls off toward the display limit with a whiter core.
                    for _ in range(4):
                        rl.draw_rectangle(48, 0, 16, 16, rl.Color(128, 153, 255, 255))
                finally:
                    rl.end_blend_mode()
        data = rl.rl_read_texture_pixels(target.texture.id, 64, 16, HDR_PIXEL_FORMAT)
        raw = bytes(ffi.buffer(data, 64 * 16 * 8))
        rl.mem_free(data)

        def float_rgb(x: int, y: int) -> tuple[float, float, float]:
            r, g, b, _ = struct.unpack_from("<4e", raw, ((15 - y) * 64 + x) * 8)
            return float(r), float(g), float(b)

        sdr = float_rgb(8, 8)
        ion_1x = float_rgb(24, 8)
        ion_2x = float_rgb(40, 8)
        ion_4x = float_rgb(56, 8)

        assert sdr == pytest.approx((120 / 255, 160 / 255, 200 / 255), abs=0.01)
        assert 0.85 < ion_1x[2] < 1.0 < ion_2x[2] < ion_4x[2] < 5.0**(1/2.2)
        assert ion_2x[2] > 1.5
        assert ion_1x[0] < ion_2x[0] < ion_4x[0]
        assert ion_4x[0] > 1.4
    finally:
        hdr.close()
        rl.unload_render_texture(target)
