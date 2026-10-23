from __future__ import annotations

import ctypes as C
import os
import sys

import pytest

from grim import canvas, edr
from grim.edr_wayland import WaylandEdr, _Dl_info, _GotSlot, _raylib_library
from grim.raylib_api import rd, rl

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or not os.environ.get("WAYLAND_DISPLAY"),
    reason="needs a Wayland compositor",
)


def test_raylib_dlsym_import_is_found_and_bound_to_libc() -> None:
    path, raylib = _raylib_library()
    info = _Dl_info()
    libc = C.CDLL(None)
    libc.dladdr.argtypes = [C.c_void_p, C.POINTER(_Dl_info)]
    assert libc.dladdr(C.cast(raylib.glfwGetPlatform, C.c_void_p), C.byref(info))
    slot = _GotSlot(path, int(info.dli_fbase), "dlsym")
    assert C.c_void_p.from_address(slot.address).value == C.cast(libc.dlsym, C.c_void_p).value


def test_window_gets_a_deep_surface_tagged_through_color_management() -> None:
    edr.reset_edr_window()
    # libdecor's GTK plugin needs a full desktop session; headless compositors draw no decorations anyway.
    rl.glfw_init_hint(rd.GLFW_WAYLAND_LIBDECOR, rd.GLFW_WAYLAND_DISABLE_LIBDECOR)
    with edr.float_backbuffer(enabled=True):
        rl.init_window(128, 96, "Wayland EDR test")
    surface = canvas.Canvas(128, 96)
    try:
        if rl.glfw_get_platform() != rd.GLFW_PLATFORM_WAYLAND:
            pytest.skip("GLFW chose X11")
        is_float, red_bits = edr.backbuffer_format()
        assert is_float or red_bits >= 10
        active = edr.activate_edr_window(True)
        # Even without HDR presentation, classic must composite through RGBA8 on the deep surface.
        assert edr.edr_available()
        if not active:
            pytest.skip("compositor lacks parametric gamma 2.2 color management")
        bridge = edr._bridge
        assert isinstance(bridge, WaylandEdr) and bridge.description is not None and bridge.wl is not None
        headroom = edr.edr_headroom()
        peak = bridge.reference * headroom
        expected = None if headroom <= 1.0 else ((bridge.reference - bridge.black) / (peak - bridge.black)) ** (1 / 2.2)
        assert edr.edr_output_gain() == pytest.approx(expected)
        surface.fit()
        for requested in (True, False, True):
            edr.activate_edr_window(requested)
            rl.begin_drawing()
            surface.draw(lambda: rl.draw_rectangle(0, 0, 128, 96, rl.Color(128, 128, 128, 255)))
            rl.end_drawing()
        # A protocol error would have killed the connection.
        assert bridge.wl.lib.wl_display_get_error(bridge.wl.display) == 0
    finally:
        surface.close()
        edr.reset_edr_window()
        rl.close_window()
