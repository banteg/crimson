from __future__ import annotations

import ctypes as C
import logging
import math
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from .raylib_api import ffi, rl

HDR_PIXEL_FORMAT = rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R16G16B16A16
_RL_ATTACHMENT_COLOR_CHANNEL0 = 0
_RL_ATTACHMENT_TEXTURE2D = 100
_log = logging.getLogger(__name__)
_macos: _MacosEdr | None = None
_edr_active = False
_headroom = 1.0


def load_float_render_texture(
    width: int, height: int, *, pixel_format: int = HDR_PIXEL_FORMAT,
) -> rl.RenderTexture:
    texture_id = int(rl.rl_load_texture(ffi.NULL, int(width), int(height), pixel_format, 1))
    if texture_id <= 0:
        raise RuntimeError("float render target texture allocation failed")
    framebuffer = int(rl.rl_load_framebuffer())
    if framebuffer <= 0:
        rl.rl_unload_texture(texture_id)
        raise RuntimeError("float framebuffer allocation failed")
    rl.rl_framebuffer_attach(
        framebuffer,
        texture_id,
        _RL_ATTACHMENT_COLOR_CHANNEL0,
        _RL_ATTACHMENT_TEXTURE2D,
        0,
    )
    if not rl.rl_framebuffer_complete(framebuffer):
        rl.rl_unload_framebuffer(framebuffer)
        rl.rl_unload_texture(texture_id)
        raise RuntimeError("float framebuffer is incomplete")
    texture = rl.Texture(texture_id, int(width), int(height), 1, pixel_format)
    rl.set_texture_filter(texture, rl.TextureFilter.TEXTURE_FILTER_BILINEAR)
    rl.set_texture_wrap(texture, rl.TextureWrap.TEXTURE_WRAP_CLAMP)
    return rl.RenderTexture(framebuffer, texture, rl.Texture(0, 0, 0, 0, 0))


class _MacosEdr:
    """Cocoa bridge for raylib's NSWindow; loaded only on macOS with an open GL context."""

    def __init__(self) -> None:
        self.objc = C.CDLL("/usr/lib/libobjc.A.dylib")
        self.objc.objc_getClass.argtypes = [C.c_char_p]
        self.objc.objc_getClass.restype = C.c_void_p
        self.objc.sel_registerName.argtypes = [C.c_char_p]
        self.objc.sel_registerName.restype = C.c_void_p
        self.objc.class_getInstanceMethod.argtypes = [C.c_void_p, C.c_void_p]
        self.objc.class_getInstanceMethod.restype = C.c_void_p
        self.objc.method_setImplementation.argtypes = [C.c_void_p, C.c_void_p]
        self.objc.method_setImplementation.restype = C.c_void_p
        self.gl = C.CDLL("/System/Library/Frameworks/OpenGL.framework/OpenGL")
        self.gl.glGetFramebufferAttachmentParameteriv.argtypes = [
            C.c_uint,
            C.c_uint,
            C.c_uint,
            C.POINTER(C.c_int),
        ]
        self.window = 0
        self.view = 0
        self.supported = False
        self.requested: bool | None = None

    def send(
        self,
        obj: int,
        selector: str,
        result: Any = C.c_void_p,
        args: tuple[Any, ...] = (),
        values: tuple[Any, ...] = (),
    ) -> Any:
        fn = C.CFUNCTYPE(result, C.c_void_p, C.c_void_p, *args)(("objc_msgSend", self.objc))
        return fn(obj, self.objc.sel_registerName(selector.encode()), *values)

    def supports(self, obj: int, selector: str) -> bool:
        return bool(
            self.send(
                obj, "respondsToSelector:", C.c_bool, (C.c_void_p,), (self.objc.sel_registerName(selector.encode()),),
            ),
        )

    @contextmanager
    def float_pixel_format(self) -> Iterator[None]:
        # GLFW has no Cocoa float-buffer hint. Scope the hook to InitWindow and
        # restore the original IMP even on failure. Keep the callback alive until then.
        # NSOpenGLPixelFormatAttribute value-taking attributes from the macOS SDK.
        valued = {7, 8, 11, 12, 13, 14, 55, 56, 70, 84, 99}
        signature = C.CFUNCTYPE(C.c_void_p, C.c_void_p, C.c_void_p, C.POINTER(C.c_uint32))
        method = self.objc.class_getInstanceMethod(
            self.objc.objc_getClass(b"NSOpenGLPixelFormat"),
            self.objc.sel_registerName(b"initWithAttributes:"),
        )
        if not method:
            _log.warning("EDR: Cocoa float pixel format unavailable; using SDR")
            yield
            return

        @signature
        def replacement(obj: int, sel: int, attrs: Any) -> int:
            rewritten: list[int] = []
            i = 0
            while attrs[i]:
                attr = int(attrs[i])
                if attr in valued:
                    if attr not in (8, 11):
                        rewritten.extend((attr, int(attrs[i + 1])))
                    i += 2
                else:
                    if attr != 58:
                        rewritten.append(attr)
                    i += 1
            # NSOpenGLPFAColorSize=64, AlphaSize=16, ColorFloat.
            rewritten.extend((8, 64, 11, 16, 58, 0))
            buffer = (C.c_uint32 * len(rewritten))(*rewritten)
            result = signature(original)(obj, sel, buffer)
            # Let GLFW create its ordinary SDR surface if float selection fails.
            if result:
                return result
            fresh = self.send(self.objc.objc_getClass(b"NSOpenGLPixelFormat"), "alloc")
            return signature(original)(fresh, sel, attrs)

        original = self.objc.method_setImplementation(method, C.cast(replacement, C.c_void_p))
        try:
            yield
        finally:
            self.objc.method_setImplementation(method, original)

    def attach(self) -> None:
        self.window = int(ffi.cast("uintptr_t", rl.get_window_handle()))
        self.view = self.send(self.window, "contentView") if self.window else 0
        self.supported = False
        if not self.view or not self.supports(self.view, "setWantsExtendedDynamicRangeOpenGLSurface:"):
            return
        # Inspect the actual default backbuffer, not an offscreen HDR texture.
        component = C.c_int()
        self.gl.glGetFramebufferAttachmentParameteriv(0x8D40, 0x0402, 0x8211, C.byref(component))
        if component.value != 0x1406:  # GL_FRAMEBUFFER_ATTACHMENT_COMPONENT_TYPE != GL_FLOAT
            _log.warning("EDR: window backbuffer is not floating point; using SDR")
            return
        self.supported = True

    def update(self, requested: bool) -> tuple[bool, float]:
        if not self.window:
            self.attach()
        if not self.supported:
            return False, 1.0
        if requested != self.requested:
            self.send(self.view, "setWantsExtendedDynamicRangeOpenGLSurface:", None, (C.c_bool,), (requested,))
            self.requested = requested
        active = requested and bool(self.send(self.view, "wantsExtendedDynamicRangeOpenGLSurface", C.c_bool))
        if not active:
            return False, 1.0
        screen = self.send(self.window, "screen")
        selector = "maximumExtendedDynamicRangeColorComponentValue"
        # Current headroom is dynamic (brightness, display moves, activation ramp).
        # Potential headroom must never be used as the current rendering limit.
        headroom = float(self.send(screen, selector, C.c_double)) if self.supports(screen, selector) else 1.0
        return True, max(1.0, headroom) if math.isfinite(headroom) else 1.0


@contextmanager
def macos_float_backbuffer(*, enabled: bool) -> Iterator[None]:
    """Reserve a float surface for windows that can switch to RTX at runtime.

    The surface alone does not enable EDR. activate_macos_edr_window follows the
    render mode, including when it starts in classic and later switches to RTX.
    """
    global _macos
    if not enabled or sys.platform != "darwin":
        yield
        return
    try:
        _macos = _MacosEdr()
    except (OSError, AttributeError):
        _log.warning("EDR: Cocoa/OpenGL bridge unavailable; using SDR", exc_info=True)
        yield
        return
    with _macos.float_pixel_format():
        yield


def activate_macos_edr_window(requested: bool) -> bool:
    """Refresh the RTX opt-in and live display headroom before drawing a frame."""
    global _edr_active, _headroom
    if _macos is None or not rl.is_window_ready():
        _edr_active, _headroom = False, 1.0
    else:
        _edr_active, _headroom = _macos.update(requested)
    return _edr_active


def reset_edr_window() -> None:
    global _macos, _edr_active, _headroom
    _macos, _edr_active, _headroom = None, False, 1.0


def edr_active() -> bool:
    return _edr_active


def edr_headroom() -> float:
    return _headroom if _edr_active else 1.0


def edr_available() -> bool:
    """Whether this window has a float surface, even while classic keeps EDR off."""
    return _macos is not None and _macos.supported
