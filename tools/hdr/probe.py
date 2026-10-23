"""Framebuffer diagnostic, NOT an HDR display detector. See README.md.

Headless: python tools/hdr/probe.py --headless-egl
Window:   PYTHONPATH=src python tools/hdr/probe.py
"""
from __future__ import annotations

import argparse
import ctypes as C
import ctypes.util
import json
import math
import sys
from contextlib import contextmanager


def function(lib, name, result, *args):
    fn = getattr(lib, name)
    fn.restype, fn.argtypes = result, list(args)
    return fn


class GL:
    def __init__(self, resolve, convention=C.CFUNCTYPE):
        def load(name, result, *args):
            address = resolve(name.encode())
            if not address or address in (1, 2, 3, C.c_void_p(-1).value):
                raise RuntimeError(f"missing GL entry point: {name}")
            return convention(result, *args)(address)

        self.integer = load("glGetIntegerv", None, C.c_uint, C.POINTER(C.c_int))
        self.string = load("glGetString", C.c_char_p, C.c_uint)
        self.error = load("glGetError", C.c_uint)
        self.bind = load("glBindFramebuffer", None, C.c_uint, C.c_uint)
        self.attachment = load("glGetFramebufferAttachmentParameteriv", None,
                               C.c_uint, C.c_uint, C.c_uint, C.POINTER(C.c_int))
        self.clamp = load("glClampColor", None, C.c_uint, C.c_uint)
        self.draw_buffer = load("glDrawBuffer", None, C.c_uint)
        self.read_buffer = load("glReadBuffer", None, C.c_uint)
        self.read = load("glReadPixels", None, C.c_int, C.c_int, C.c_int, C.c_int,
                         C.c_uint, C.c_uint, C.c_void_p)
        self.enable = load("glEnable", None, C.c_uint)
        self.disable = load("glDisable", None, C.c_uint)
        self.scissor = load("glScissor", None, C.c_int, C.c_int, C.c_int, C.c_int)
        self.clear = load("glClearBufferfv", None, C.c_uint, C.c_int, C.POINTER(C.c_float))

    def inspect_and_draw(self, width, height):
        # Own the probe's frame; never call this inside the game renderer.
        if self.error():
            raise RuntimeError("pre-existing GL error")
        self.bind(0x8D40, 0)  # GL_FRAMEBUFFER: inspect actual window/pbuffer, not an FBO
        double = C.c_int()
        self.integer(0x0C32, C.byref(double))  # GL_DOUBLEBUFFER
        attachment = 0x0402 if double.value else 0x0400  # BACK_LEFT / FRONT_LEFT
        component, bits = C.c_int(), C.c_int()
        self.attachment(0x8D40, attachment, 0x8211, C.byref(component))
        self.attachment(0x8D40, attachment, 0x8212, C.byref(bits))
        self.disable(0x8DB9)  # FRAMEBUFFER_SRGB: these patches contain linear numeric values
        self.disable(0x0BD0)  # DITHER
        self.clamp(0x891C, 0)  # CLAMP_READ_COLOR = FALSE
        self.draw_buffer(0x0405 if double.value else 0x0404)
        self.read_buffer(0x0405 if double.value else 0x0404)  # BACK / FRONT
        self.enable(0x0C11)  # SCISSOR_TEST
        samples = []
        for index, value in enumerate((0.25, 1.0, 2.0, 4.0)):
            left, right = index * width // 4, (index + 1) * width // 4
            self.scissor(left, 0, right - left, height)
            self.clear(0x1800, 0, (C.c_float * 4)(value, value, value, 1))
            pixel = (C.c_float * 4)()
            self.read((left + right) // 2, height // 2, 1, 1, 0x1908, 0x1406, pixel)
            samples.append(list(pixel))
        self.disable(0x0C11)
        error = self.error()
        if error:
            raise RuntimeError(f"GL probe error: {error:#x}")
        return {
            "gl_vendor": self.string(0x1F00).decode(),
            "gl_renderer": self.string(0x1F01).decode(),
            "gl_version": self.string(0x1F02).decode(),
            "default_component_type": hex(component.value),
            "default_red_bits": bits.value,
            "double_buffered": bool(double.value),
            "written": [0.25, 1, 2, 4],
            "read_rgba": samples,
            "extended_values_survive": component.value == 0x1406 and samples[-1][0] > 3.9,
            "physical_hdr_verified": False,
        }


@contextmanager
def egl_context(floating):
    """Linux Mesa surfaceless pbuffer: deliberately has NO compositor/display."""
    lib = C.CDLL(ctypes.util.find_library("EGL") or "libEGL.so.1")
    get_proc = function(lib, "eglGetProcAddress", C.c_void_p, C.c_char_p)
    platform = function(lib, "eglGetPlatformDisplay", C.c_void_p, C.c_uint, C.c_void_p, C.c_void_p)
    display = platform(0x31DD, None, None)  # EGL_PLATFORM_SURFACELESS_MESA
    init = function(lib, "eglInitialize", C.c_uint, C.c_void_p, C.c_void_p, C.c_void_p)
    if not display or not init(display, None, None):
        raise RuntimeError("surfaceless EGL initialization failed")
    terminate = function(lib, "eglTerminate", C.c_uint, C.c_void_p)
    destroy_surface = function(lib, "eglDestroySurface", C.c_uint, C.c_void_p, C.c_void_p)
    destroy_context = function(lib, "eglDestroyContext", C.c_uint, C.c_void_p, C.c_void_p)
    make_current = function(lib, "eglMakeCurrent", C.c_uint, C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p)
    surface = context = None
    try:
        query = function(lib, "eglQueryString", C.c_char_p, C.c_void_p, C.c_int)
        extensions = query(display, 0x3055).decode().split()
        if floating and "EGL_EXT_pixel_format_float" not in extensions:
            raise RuntimeError("EGL_EXT_pixel_format_float unavailable")
        bind = function(lib, "eglBindAPI", C.c_uint, C.c_uint)
        if not bind(0x30A2):  # EGL_OPENGL_API
            raise RuntimeError("EGL OpenGL unavailable")
        attrs = [0x3033, 1, 0x3040, 8]  # PBUFFER_BIT, OPENGL_BIT
        for channel in (0x3024, 0x3023, 0x3022, 0x3021):
            attrs += [channel, 16 if floating else 8]
        if floating:
            attrs += [0x3339, 0x333B]  # COLOR_COMPONENT_TYPE_EXT, FLOAT_EXT
        attrs += [0x3038]
        choose = function(lib, "eglChooseConfig", C.c_uint, C.c_void_p, C.POINTER(C.c_int),
                          C.POINTER(C.c_void_p), C.c_int, C.POINTER(C.c_int))
        config, count = C.c_void_p(), C.c_int()
        if not choose(display, (C.c_int * len(attrs))(*attrs), C.byref(config), 1, C.byref(count)) or not count.value:
            raise RuntimeError("no matching pbuffer config")
        create_surface = function(lib, "eglCreatePbufferSurface", C.c_void_p,
                                  C.c_void_p, C.c_void_p, C.POINTER(C.c_int))
        surface = create_surface(display, config, (C.c_int * 5)(0x3057, 16, 0x3056, 4, 0x3038))
        create_context = function(lib, "eglCreateContext", C.c_void_p,
                                  C.c_void_p, C.c_void_p, C.c_void_p, C.POINTER(C.c_int))
        context = create_context(display, config, None,
                                 (C.c_int * 7)(0x3098, 3, 0x30FB, 3, 0x30FD, 1, 0x3038))
        if not surface or not context or not make_current(display, surface, surface, context):
            raise RuntimeError("EGL pbuffer/context creation failed")
        yield GL(get_proc)
    finally:
        make_current(display, None, None, None)
        if context:
            destroy_context(display, context)
        if surface:
            destroy_surface(display, surface)
        terminate(display)


def window_probe():
    # Use exactly the application's current window setup; no hidden WGL hooks.
    from grim import edr
    from grim.raylib_api import rl

    if sys.platform == "win32":
        library = C.WinDLL("opengl32")
        extension = function(library, "wglGetProcAddress", C.c_void_p, C.c_char_p)
        def resolve(name):
            address = extension(name)
            if address and address not in (1, 2, 3, C.c_void_p(-1).value):
                return address
            return C.cast(getattr(library, name.decode()), C.c_void_p).value
        convention = C.WINFUNCTYPE
    elif sys.platform == "darwin":
        library = C.CDLL("/System/Library/Frameworks/OpenGL.framework/OpenGL")
        def resolve(name):
            return C.cast(getattr(library, name.decode()), C.c_void_p).value
        convention = C.CFUNCTYPE
    else:
        library = C.CDLL(ctypes.util.find_library("EGL") or "libEGL.so.1")
        resolve = function(library, "eglGetProcAddress", C.c_void_p, C.c_char_p)
        convention = C.CFUNCTYPE
    edr.reset_edr_window()
    rl.set_config_flags(rl.ConfigFlags.FLAG_WINDOW_RESIZABLE)
    with edr.macos_float_backbuffer(enabled=True):
        rl.init_window(960, 360, "Framebuffer probe: F11 borderless, Esc exit (not an HDR detector)")
    try:
        gl = GL(resolve, convention)
        rl.set_target_fps(30)
        previous = None
        while not rl.window_should_close():
            if rl.is_key_pressed(rl.KeyboardKey.KEY_F11):
                rl.toggle_borderless_windowed()
            edr.activate_macos_edr_window(True)
            width, height = rl.get_render_width(), rl.get_render_height()
            if min(width, height) < 4:
                continue
            rl.begin_drawing()
            rl.rl_draw_render_batch_active()
            report = gl.inspect_and_draw(width, height)
            report.update(platform=sys.platform, size=[width, height], monitor=rl.get_current_monitor(),
                          borderless=rl.is_window_state(rl.ConfigFlags.FLAG_BORDERLESS_WINDOWED_MODE))
            if report != previous:
                print(json.dumps(report), flush=True)
                previous = report
            rl.end_drawing()
    finally:
        edr.reset_edr_window()
        rl.close_window()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--headless-egl", action="store_true")
    args = parser.parse_args()
    if args.headless_egl:
        for floating in (False, True):
            with egl_context(floating) as gl:
                report = gl.inspect_and_draw(16, 4)
                report.update(surface="surfaceless EGL pbuffer", requested_float=floating)
                print(json.dumps(report), flush=True)
                # A negative control and a positive control, not HDR detection.
                if report["extended_values_survive"] != floating:
                    raise RuntimeError("unexpected fixed/float readback result")
                for value, pixel in zip(report["written"], report["read_rgba"], strict=True):
                    expected = value if floating else min(value, 1.0)
                    if any(not math.isclose(channel, expected, abs_tol=0.005) for channel in pixel[:3]):
                        raise RuntimeError("unexpected patch readback")
    else:
        window_probe()


if __name__ == "__main__":
    main()
