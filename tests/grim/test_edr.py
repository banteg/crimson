from __future__ import annotations

import pytest

from grim import edr
from grim.raylib_api import rl
from grim.texture_mode import current_target_edr_headroom, texture_mode


def test_edr_request_is_retained_while_current_headroom_is_one(mocker) -> None:
    bridge = mocker.Mock()
    bridge.update.side_effect = [(True, 1.0), (True, 7.5), (False, 1.0)]
    mocker.patch.object(edr, "_bridge", bridge)
    mocker.patch.object(rl, "is_window_ready", return_value=True)
    try:
        assert edr.activate_edr_window(True)
        assert edr.edr_headroom() == 1.0
        assert edr.activate_edr_window(True)
        assert edr.edr_headroom() == 7.5
        assert not edr.activate_edr_window(False)
        assert edr.edr_headroom() == 1.0
        assert bridge.update.call_args_list == [mocker.call(True), mocker.call(True), mocker.call(False)]
    finally:
        edr.reset_edr_window()
    assert not edr.edr_active()


def test_float_allocation_failure_releases_partial_resources(mocker) -> None:
    mocker.patch.object(rl, "rl_load_texture", return_value=42)
    mocker.patch.object(rl, "rl_load_framebuffer", return_value=43)
    mocker.patch.object(rl, "rl_framebuffer_attach")
    mocker.patch.object(rl, "rl_framebuffer_complete", return_value=False)
    unload_texture = mocker.patch.object(rl, "rl_unload_texture")
    unload_framebuffer = mocker.patch.object(rl, "rl_unload_framebuffer")
    with pytest.raises(RuntimeError, match="incomplete"):
        edr.load_float_render_texture(64, 64)
    unload_texture.assert_called_once_with(42)
    unload_framebuffer.assert_called_once_with(43)


def test_sdr_ancestor_forces_sdr_tonemapping_even_inside_float_target(mocker) -> None:
    mocker.patch.object(edr, "_edr_active", True)
    mocker.patch.object(edr, "_headroom", 5.0)
    for name in ("begin_texture_mode", "end_texture_mode", "rl_scalef"):
        mocker.patch.object(rl, name)
    sdr = rl.RenderTexture()
    sdr.texture.format = rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R8G8B8A8
    hdr = rl.RenderTexture()
    hdr.texture.format = edr.HDR_PIXEL_FORMAT
    assert current_target_edr_headroom() == 5.0
    with texture_mode(sdr), texture_mode(hdr):
        assert current_target_edr_headroom() == 1.0
    assert current_target_edr_headroom() == 5.0


def test_non_macos_does_not_load_cocoa(mocker) -> None:
    mocker.patch.object(edr.sys, "platform", "win32")
    bridge = mocker.patch.object(edr, "_MacosEdr")
    with edr.float_backbuffer(enabled=True):
        pass
    bridge.assert_not_called()
