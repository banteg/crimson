from __future__ import annotations

import os
import sys
from collections.abc import Iterator

import pytest

from grim.raylib_api import rl


def _can_init_raylib() -> bool:
    if sys.platform == "darwin":
        import ctypes
        import ctypes.util

        lib_path = ctypes.util.find_library("CoreGraphics")
        if not lib_path:
            return False
        try:
            cg = ctypes.CDLL(lib_path)
        except OSError:
            return False

        # CGGetActiveDisplayList(uint32_t maxDisplays, uint32_t *activeDisplays, uint32_t *displayCount)
        get_active_display_list = cg.CGGetActiveDisplayList
        get_active_display_list.argtypes = [
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32),
        ]
        get_active_display_list.restype = ctypes.c_int32

        max_displays = 16
        active = (ctypes.c_uint32 * max_displays)()
        count = ctypes.c_uint32()
        err = get_active_display_list(max_displays, active, ctypes.byref(count))
        return err == 0 and count.value > 0

    if sys.platform.startswith("linux"):
        if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            return False
    return True


@pytest.fixture(scope="module")
def raylib_context() -> Iterator[None]:
    if not _can_init_raylib():
        pytest.skip("raylib requires a display accessible to this process (check sandbox access)")
    rl.set_config_flags(int(rl.ConfigFlags.FLAG_WINDOW_HIDDEN | rl.ConfigFlags.FLAG_WINDOW_HIGHDPI))
    rl.init_window(128, 96, "render-tests")
    try:
        yield
    finally:
        rl.close_window()
