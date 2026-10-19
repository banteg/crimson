from __future__ import annotations

import ctypes as C
import sys

import pytest

from crimson.game.loop_view import GameLoopView
from crimson.render.rtx.hdr import HdrRenderer
from grim import canvas, edr
from grim.geom import Vec2
from grim.raylib_api import rl


@pytest.mark.skipif(sys.platform != "darwin", reason="Cocoa EDR window integration requires macOS")
@pytest.mark.parametrize("letterbox", [False, True])
@pytest.mark.parametrize("gain", [1.0, 1.5])
def test_edr_survives_world_gamma_canvas_and_classic_toggle(
    raylib_display, make_game_state, mocker, letterbox, gain,
) -> None:
    edr.reset_edr_window()
    rl.set_config_flags(rl.ConfigFlags.FLAG_WINDOW_HIDDEN | rl.ConfigFlags.FLAG_WINDOW_HIGHDPI)
    with edr.macos_float_backbuffer(enabled=True):
        rl.init_window(128, 96, "EDR pipeline test")
    game = GameLoopView(make_game_state())
    game.state.gamma_ramp = gain
    surface = canvas.Canvas(64 if letterbox else 128, 96)
    hdr = HdrRenderer()
    gl = C.CDLL("/System/Library/Frameworks/OpenGL.framework/OpenGL")
    gl.glReadPixels.argtypes = [C.c_int, C.c_int, C.c_int, C.c_int, C.c_uint, C.c_uint, C.c_void_p]
    gl.glClampColor.argtypes = [C.c_uint, C.c_uint]
    gl.glReadBuffer.argtypes = [C.c_uint]

    def sample(x: float, y: float) -> tuple[float, float, float]:
        rl.rl_draw_render_batch_active()
        pixel = (C.c_float * 4)()
        gl.glClampColor(0x891C, 0)  # GL_CLAMP_READ_COLOR = GL_FALSE
        gl.glReadBuffer(0x0405)  # GL_BACK, before presentation
        gl.glReadPixels(int(x * rl.get_render_width()), int(y * rl.get_render_height()), 1, 1, 0x1908, 0x1406, pixel)
        return tuple(pixel[:3])

    def draw_world() -> None:
        with hdr.scope(out_size=Vec2(canvas.width(), canvas.height())):
            for _ in range(4):
                rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
                rl.draw_rectangle(0, 0, canvas.width(), canvas.height(), rl.Color(128, 153, 255, 255))
                rl.end_blend_mode()
        # HUD is drawn outside the HDR world pass and must remain SDR.
        rl.draw_rectangle(0, 0, canvas.width(), canvas.height() // 2, rl.Color(128, 128, 128, 255))

    try:
        assert edr.activate_macos_edr_window(True)
        assert edr.edr_available()
        # Hidden test windows don't raise display headroom. A controlled value
        # tests the entire real float pipeline independently of display brightness.
        mocker.patch.object(edr, "_headroom", 5.0)
        mocker.patch.object(game, "_draw_scene_layers", side_effect=draw_world)
        surface.fit()
        rl.begin_drawing()
        surface.draw(game.draw)
        highlight = sample(0.5, 0.25)
        ui = sample(0.5, 0.75)
        assert 1.5 < highlight[2] < 5.0 ** (1 / 2.2)
        assert ui == pytest.approx((128 / 255 * gain,) * 3, abs=0.01)
        if letterbox:
            assert surface._target is not None
            assert surface._target.texture.format == edr.HDR_PIXEL_FORMAT
        if gain != 1.0:
            assert hdr.target is not None
            assert game._gamma_target is not None
            assert game._gamma_target.texture.format == edr.HDR_PIXEL_FORMAT
            assert (game._gamma_target.texture.width, game._gamma_target.texture.height) == (
                hdr.target.texture.width,
                hdr.target.texture.height,
            )
        rl.end_drawing()

        assert not edr.activate_macos_edr_window(False)
        assert edr.edr_headroom() == 1.0

        def classic_scene() -> None:
            rl.clear_background(rl.BLACK)
            rl.begin_blend_mode(rl.BlendMode.BLEND_ADDITIVE)
            for _ in range(2):
                rl.draw_rectangle(0, 0, canvas.width(), canvas.height(), rl.Color(192, 0, 0, 255))
            rl.end_blend_mode()
            rl.draw_rectangle(0, 0, canvas.width(), canvas.height(), rl.Color(0, 0, 255, 128))

        mocker.patch.object(game, "_draw_scene_layers", side_effect=classic_scene)
        rl.begin_drawing()
        surface.draw(game.draw)
        # The two red draws saturate before the half-opacity blue draw, just as
        # on an ordinary RGBA8 window, even though the reserved surface is float.
        assert sample(0.5, 0.5) == pytest.approx((127 / 255 * gain, 0, 128 / 255 * gain), abs=0.01)
        assert surface._target is not None
        assert surface._target.texture.format == rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R8G8B8A8
        rl.end_drawing()
    finally:
        hdr.close()
        game._close_gamma_resources()
        surface.close()
        edr.reset_edr_window()
        rl.close_window()


@pytest.mark.skipif(sys.platform != "darwin", reason="Cocoa hook requires macOS")
def test_cocoa_pixel_format_hook_is_restored_on_exception() -> None:
    bridge = edr._MacosEdr()
    objc = bridge.objc
    objc.method_getImplementation.argtypes = [C.c_void_p]
    objc.method_getImplementation.restype = C.c_void_p
    method = objc.class_getInstanceMethod(objc.objc_getClass(b"NSOpenGLPixelFormat"),
                                         objc.sel_registerName(b"initWithAttributes:"))
    original = objc.method_getImplementation(method)
    with pytest.raises(RuntimeError, match="window setup failed"), bridge.float_pixel_format():
        assert objc.method_getImplementation(method) != original
        raise RuntimeError("window setup failed")
    assert objc.method_getImplementation(method) == original
