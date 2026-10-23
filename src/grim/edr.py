from __future__ import annotations

import ctypes as C
import logging
import math
import sys
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from typing import Any, Protocol

from .raylib_api import ffi, rl

HDR_PIXEL_FORMAT = rl.PixelFormat.PIXELFORMAT_UNCOMPRESSED_R16G16B16A16
_RL_ATTACHMENT_COLOR_CHANNEL0 = 0
_RL_ATTACHMENT_TEXTURE2D = 100
_log = logging.getLogger(__name__)


class _Bridge(Protocol):
    """A platform's deep window surface and its HDR presentation switch."""

    supported: bool

    def float_pixel_format(self) -> AbstractContextManager[None]: ...

    def update(self, requested: bool) -> tuple[bool, float]: ...

    def output_gain(self, headroom: float, /) -> float | None:
        """What the active surface needs the gamma-domain frame multiplied by, or None to present it as drawn."""
        ...

    def close(self) -> None: ...


_bridge: _Bridge | None = None
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
        if not backbuffer_format()[0]:
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

    def output_gain(self, _headroom: float) -> None:
        # EDR OpenGL surfaces take the extended gamma-domain frame as drawn.
        return None

    def close(self) -> None:
        pass


def backbuffer_format() -> tuple[bool, int]:
    """Whether the window's actual default backbuffer (not an offscreen HDR texture) is float, and its red bits."""
    query = C.CFUNCTYPE(None, C.c_uint, C.c_uint, C.c_uint, C.POINTER(C.c_int))(
        int(ffi.cast("uintptr_t", rl.glfw_get_proc_address("glGetFramebufferAttachmentParameteriv"))),
    )
    component, red = C.c_int(), C.c_int()
    # GL_FRAMEBUFFER, GL_BACK_LEFT: GL_FRAMEBUFFER_ATTACHMENT_COMPONENT_TYPE, _RED_SIZE
    query(0x8D40, 0x0402, 0x8211, C.byref(component))
    query(0x8D40, 0x0402, 0x8212, C.byref(red))
    return component.value == 0x1406, red.value


def _platform_bridge() -> _Bridge | None:
    if sys.platform == "darwin":
        return _MacosEdr()
    if sys.platform == "linux":
        from .edr_wayland import WaylandEdr

        return WaylandEdr()
    return None


@contextmanager
def float_backbuffer(*, enabled: bool) -> Iterator[None]:
    """Reserve a float surface for windows that can switch to RTX at runtime.

    The surface alone does not enable EDR. activate_edr_window follows the
    render mode, including when it starts in classic and later switches to RTX.
    """
    global _bridge
    if not enabled:
        yield
        return
    try:
        _bridge = _platform_bridge()
    except (OSError, AttributeError, StopIteration):
        _log.warning("EDR: platform bridge unavailable; using SDR", exc_info=True)
        yield
        return
    if _bridge is None:
        yield
        return
    with _bridge.float_pixel_format():
        yield


def activate_edr_window(requested: bool) -> bool:
    """Refresh the RTX opt-in and live display headroom before drawing a frame."""
    global _edr_active, _headroom
    if _bridge is None or not rl.is_window_ready():
        _edr_active, _headroom = False, 1.0
    else:
        _edr_active, _headroom = _bridge.update(requested)
    return _edr_active


def reset_edr_window() -> None:
    global _bridge, _edr_active, _headroom
    if _bridge is not None:
        _bridge.close()
    _bridge, _edr_active, _headroom = None, False, 1.0


def edr_active() -> bool:
    return _edr_active


def edr_headroom() -> float:
    return _headroom if _edr_active else 1.0


def edr_available() -> bool:
    """Whether this window has a float surface, even while classic keeps EDR off."""
    return _bridge is not None and _bridge.supported


def edr_output_gain() -> float | None:
    """The gain the active EDR surface needs on the gamma-domain frame, or None to present it as drawn."""
    if not _edr_active or _bridge is None:
        return None
    return _bridge.output_gain(_headroom)
