"""Wayland HDR: a float EGL window surface tagged through wp_color_management_v1.

Mesa's EGL leaves Wayland color management to the client, and raylib resets GLFW's window hints inside
InitWindow, so there is no way to ask for a deeper framebuffer. Window creation instead narrows the EGLConfig
list GLFW chooses from, the way the Cocoa bridge narrows NSOpenGLPixelFormat: RGBA16F where the driver and
compositor share a float buffer format, else 10 bits per channel.

The surface is described as gamma 2.2 sRGB whose signal 1.0 is the display's peak and whose reference white is
the compositor's own. The game keeps its macOS meaning of "1.0 is SDR white, headroom is the multiple above
it": the RTX shoulder already limits highlights to headroom**(1/2.2) in its gamma domain, so presenting the
frame divided by that limit lands SDR white on the reference level and the shoulder's ceiling on the peak.
That signal never exceeds 1.0, so a 10-bit surface carries it as well as a float one.
"""

from __future__ import annotations

import ctypes as C
import logging
import math
import os
import struct
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any

import raylib

from .edr import backbuffer_format
from .raylib_api import ffi, rd, rl

_log = logging.getLogger(__name__)

# EGL and EGL_EXT_pixel_format_float / EGL_EXT_present_opaque tokens.
_EGL_ALPHA_SIZE = 0x3021
_EGL_RED_SIZE = 0x3024
_EGL_SURFACE_TYPE = 0x3033
_EGL_RENDERABLE_TYPE = 0x3040
_EGL_EXTENSIONS = 0x3055
_EGL_WINDOW_BIT = 0x0004
_EGL_OPENGL_BIT = 0x0008
_EGL_COLOR_COMPONENT_TYPE_EXT = 0x3339
_EGL_COLOR_COMPONENT_TYPE_FLOAT_EXT = 0x333B

# color-management-v1 enums.
_FEATURE_PARAMETRIC = 1
_FEATURE_SET_LUMINANCES = 4
_PRIMARIES_SRGB = 1
_TF_GAMMA22 = 2
_INTENT_PERCEPTUAL = 0

# Wire signatures for the interfaces this client touches, in protocol opcode order (staging color-management-v1,
# version 3). Each message is name:signature[:types], types naming the interface of each object/new_id argument.
_COLOR_MANAGEMENT_V1 = {
    "wp_color_manager_v1": (
        (
            "destroy: get_output:no:wp_color_management_output_v1,wl_output "
            "get_surface:no:wp_color_management_surface_v1,wl_surface "
            "get_surface_feedback:no:wp_color_management_surface_feedback_v1,wl_surface "
            "create_icc_creator:n:wp_image_description_creator_icc_v1 "
            "create_parametric_creator:n:wp_image_description_creator_params_v1 "
            "create_windows_scrgb:n:wp_image_description_v1 "
            "get_image_description:2no:wp_image_description_v1,wp_image_description_reference_v1 "
            "create_windows_bt2100:3n:wp_image_description_v1"
        ),
        "supported_intent:u supported_feature:u supported_tf_named:u supported_primaries_named:u done:",
    ),
    "wp_color_management_output_v1": (
        "destroy: get_image_description:n:wp_image_description_v1",
        "image_description_changed:",
    ),
    "wp_color_management_surface_v1": (
        "destroy: set_image_description:ou:wp_image_description_v1, unset_image_description:",
        "",
    ),
    "wp_color_management_surface_feedback_v1": (
        "destroy: get_preferred:n:wp_image_description_v1 get_preferred_parametric:n:wp_image_description_v1",
        "preferred_changed:u preferred_changed2:2uu",
    ),
    "wp_image_description_creator_icc_v1": ("create:n:wp_image_description_v1 set_icc_file:huu", ""),
    "wp_image_description_creator_params_v1": (
        (
            "create:n:wp_image_description_v1 set_tf_named:u set_tf_power:u set_primaries_named:u "
            "set_primaries:iiiiiiii set_luminances:uuu set_mastering_display_primaries:iiiiiiii "
            "set_mastering_luminance:uu set_max_cll:u set_max_fall:u"
        ),
        "",
    ),
    "wp_image_description_v1": (
        "destroy: get_information:n:wp_image_description_info_v1",
        "failed:us ready:u ready2:2uu",
    ),
    "wp_image_description_info_v1": (
        "",
        (
            "done: icc_file:hu primaries:iiiiiiii primaries_named:u tf_power:u tf_named:u luminances:uuu "
            "target_primaries:iiiiiiii target_luminance:uu target_max_cll:u target_max_fall:u"
        ),
    ),
    "wp_image_description_reference_v1": ("destroy:", ""),
}


def _address(function: Any) -> int:
    return C.cast(function, C.c_void_p).value or 0


def _raylib_library() -> tuple[str, C.CDLL]:
    path = next(Path(raylib.__file__).parent.glob("_raylib_cffi*.so"))
    return str(path), C.CDLL(str(path))


class _GotSlot:
    """One imported function's GOT entry in a loaded ELF image, swapped while a scope runs."""

    def __init__(self, path: str, base: int, symbol: str) -> None:
        data = Path(path).read_bytes()
        shoff, = struct.unpack_from("<Q", data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
        sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
        names = sections[shstrndx]

        def section(name: str) -> tuple[int, ...]:
            for header in sections:
                end = data.index(b"\0", names[4] + header[0])
                if data[names[4] + header[0]:end].decode() == name:
                    return header
            raise LookupError(name)

        dynsym, dynstr = section(".dynsym"), section(".dynstr")
        self.address = 0
        for table in (".rela.plt", ".rela.dyn"):
            rela = section(table)
            for offset in range(rela[4], rela[4] + rela[5], 24):
                r_offset, r_info = struct.unpack_from("<QQ", data, offset)
                name_offset, = struct.unpack_from("<I", data, dynsym[4] + (r_info >> 32) * 24)
                start = dynstr[4] + name_offset
                if data[start:data.index(b"\0", start)].decode() == symbol:
                    self.address = base + r_offset
                    return
        raise LookupError(symbol)

    @contextmanager
    def replaced(self, function: int) -> Iterator[int]:
        libc = C.CDLL(None, use_errno=True)
        libc.mprotect.argtypes = [C.c_void_p, C.c_size_t, C.c_int]
        size = os.sysconf("SC_PAGE_SIZE")
        page = self.address & ~(size - 1)
        protection = _page_protection(page)
        slot = C.c_void_p.from_address(self.address)
        original = int(slot.value or 0)
        # Full RELRO leaves the GOT read-only after loading.
        if libc.mprotect(page, size, 0x1 | 0x2) != 0:
            raise OSError(C.get_errno(), "mprotect")
        slot.value = function
        try:
            yield original
        finally:
            slot.value = original
            libc.mprotect(page, size, protection)


def _page_protection(address: int) -> int:
    for line in Path("/proc/self/maps").read_text().splitlines():
        span, perms = line.split()[:2]
        start, end = (int(part, 16) for part in span.split("-"))
        if start <= address < end:
            return (0x1 if perms[0] == "r" else 0) | (0x2 if perms[1] == "w" else 0) | (0x4 if perms[2] == "x" else 0)
    raise LookupError(hex(address))


class _Dl_info(C.Structure):
    _fields_ = [("dli_fname", C.c_char_p), ("dli_fbase", C.c_void_p),
                ("dli_sname", C.c_char_p), ("dli_saddr", C.c_void_p)]


_DLSYM = C.CFUNCTYPE(C.c_void_p, C.c_void_p, C.c_char_p)
_EGL_GET_CONFIGS = C.CFUNCTYPE(C.c_uint, C.c_void_p, C.POINTER(C.c_void_p), C.c_int, C.POINTER(C.c_int))
_EGL_GET_CONFIG_ATTRIB = C.CFUNCTYPE(C.c_uint, C.c_void_p, C.c_void_p, C.c_int, C.POINTER(C.c_int))
_EGL_QUERY_STRING = C.CFUNCTYPE(C.c_char_p, C.c_void_p, C.c_int)


class _WlMessage(C.Structure):
    _fields_ = [("name", C.c_char_p), ("signature", C.c_char_p), ("types", C.POINTER(C.c_void_p))]


class _WlInterface(C.Structure):
    _fields_ = [("name", C.c_char_p), ("version", C.c_int),
                ("method_count", C.c_int), ("methods", C.POINTER(_WlMessage)),
                ("event_count", C.c_int), ("events", C.POINTER(_WlMessage))]


class _WlArgument(C.Union):
    _fields_ = [("i", C.c_int32), ("u", C.c_uint32), ("s", C.c_char_p), ("o", C.c_void_p), ("n", C.c_uint32)]


_DISPATCHER = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_uint32, C.c_void_p, C.POINTER(_WlArgument))
_MARSHAL_FLAG_DESTROY = 1


class _Wayland:
    """libwayland-client on GLFW's own display, with a private event queue so GLFW's dispatch never runs ours."""

    def __init__(self, display: int) -> None:
        lib = C.CDLL("libwayland-client.so.0")
        for name, restype, argtypes in (
            ("wl_display_create_queue", C.c_void_p, [C.c_void_p]),
            ("wl_event_queue_destroy", None, [C.c_void_p]),
            ("wl_proxy_create_wrapper", C.c_void_p, [C.c_void_p]),
            ("wl_proxy_wrapper_destroy", None, [C.c_void_p]),
            ("wl_proxy_set_queue", None, [C.c_void_p, C.c_void_p]),
            ("wl_proxy_get_version", C.c_uint32, [C.c_void_p]),
            ("wl_proxy_destroy", None, [C.c_void_p]),
            ("wl_proxy_add_dispatcher", C.c_int, [C.c_void_p, _DISPATCHER, C.c_void_p, C.c_void_p]),
            ("wl_proxy_marshal_array_flags", C.c_void_p,
             [C.c_void_p, C.c_uint32, C.c_void_p, C.c_uint32, C.c_uint32, C.POINTER(_WlArgument)]),
            ("wl_display_roundtrip_queue", C.c_int, [C.c_void_p, C.c_void_p]),
            ("wl_display_dispatch_queue_pending", C.c_int, [C.c_void_p, C.c_void_p]),
            ("wl_display_flush", C.c_int, [C.c_void_p]),
            ("wl_display_get_error", C.c_int, [C.c_void_p]),
        ):
            function = getattr(lib, name)
            function.restype, function.argtypes = restype, argtypes
        self.lib = lib
        self.display = display
        self.queue = lib.wl_display_create_queue(display)
        self.interfaces = {name: C.addressof(_WlInterface.in_dll(lib, f"{name}_interface"))
                           for name in ("wl_registry", "wl_surface", "wl_output")}
        # Interfaces refer to each other, so allocate them all before filling in their message tables.
        own = {name: _WlInterface(name.encode(), 3) for name in _COLOR_MANAGEMENT_V1}
        self.interfaces.update((name, C.addressof(interface)) for name, interface in own.items())
        self._keep: list[Any] = list(own.values())
        for name, (requests, events) in _COLOR_MANAGEMENT_V1.items():
            own[name].method_count, own[name].methods = self._messages(requests)
            own[name].event_count, own[name].events = self._messages(events)
        self._handlers: dict[int, Callable[[int, Any], None]] = {}
        self._dispatcher = _DISPATCHER(self._dispatch)

    def _messages(self, spec: str) -> tuple[int, Any]:
        entries = [entry.split(":") for entry in spec.split()]
        messages = (_WlMessage * max(1, len(entries)))()
        for message, (name, signature, *types) in zip(messages, entries, strict=False):
            names = types[0].split(",") if types else []
            arguments = sum(ch.isalpha() for ch in signature)
            table = (C.c_void_p * max(1, arguments))(*(self.interfaces.get(n) for n in names))
            message.name, message.signature, message.types = name.encode(), signature.encode(), table
            self._keep.extend((message.name, message.signature, table))
        self._keep.append(messages)
        return len(entries), messages

    def _dispatch(self, _impl: int, target: int, opcode: int, _message: int, args: Any) -> int:
        handler = self._handlers.get(target)
        if handler is not None:
            handler(opcode, args)
        return 0

    def request(self, proxy: int, opcode: int, *args: int | bytes | None,
                interface: str | None = None, version: int = 0, destroy: bool = False) -> int:
        """Send a request; a new_id slot is passed as None and the new proxy, if any, is returned."""
        values = (_WlArgument * max(1, len(args)))()
        for value, arg in zip(values, args, strict=False):
            if isinstance(arg, bytes):
                value.s = arg
            elif arg is not None:
                value.o = arg  # objects, and on little-endian hosts the int/uint members too
        created = self.lib.wl_proxy_marshal_array_flags(
            proxy, opcode, self.interfaces[interface] if interface else None,
            version or self.lib.wl_proxy_get_version(proxy), _MARSHAL_FLAG_DESTROY if destroy else 0, values,
        )
        return int(created or 0)

    def listen(self, proxy: int, handler: Callable[[int, Any], None]) -> int:
        self._handlers[proxy] = handler
        self.lib.wl_proxy_add_dispatcher(proxy, self._dispatcher, None, None)
        return proxy

    def forget(self, proxy: int) -> None:
        self._handlers.pop(proxy, None)

    def roundtrip(self) -> None:
        if self.lib.wl_display_roundtrip_queue(self.display, self.queue) < 0:
            raise OSError(self.lib.wl_display_get_error(self.display), "wayland roundtrip failed")

    def dispatch_pending(self) -> None:
        self.lib.wl_display_dispatch_queue_pending(self.display, self.queue)

    def flush(self) -> None:
        self.lib.wl_display_flush(self.display)

    def bind_global(self, interface: str, version: int) -> int | None:
        """Bind a global through a registry on the private queue."""
        wrapper = self.lib.wl_proxy_create_wrapper(self.display)
        self.lib.wl_proxy_set_queue(wrapper, self.queue)
        registry = self.request(wrapper, 1, None, interface="wl_registry", version=1)  # wl_display.get_registry
        self.lib.wl_proxy_wrapper_destroy(wrapper)
        found: dict[str, tuple[int, int]] = {}

        def on_registry(opcode: int, args: Any) -> None:
            if opcode == 0:  # global(name, interface, version)
                found[args[1].s.decode()] = (args[0].u, args[2].u)

        self.listen(registry, on_registry)
        self.roundtrip()
        self.forget(registry)
        bound = None
        if interface in found:
            name, offered = found[interface]
            version = min(version, offered)
            # wl_registry.bind(name, interface, version, new_id), new_id untyped on the wire.
            values = (_WlArgument * 4)()
            values[0].u, values[1].s, values[2].u = name, interface.encode(), version
            bound = int(self.lib.wl_proxy_marshal_array_flags(
                registry, 0, self.interfaces[interface], version, 0, values) or 0)
        self.lib.wl_proxy_destroy(registry)
        return bound

    def close(self) -> None:
        self.lib.wl_event_queue_destroy(self.queue)


class _ImageDescription:
    """Wait for a wp_image_description_v1 to become ready, optionally reading its information."""

    def __init__(self, wl: _Wayland, proxy: int, *, read_info: bool) -> None:
        self.wl, self.proxy = wl, proxy
        self.ready: bool | None = None
        self.info: dict[str, tuple[int, ...]] = {}
        self._read_info = read_info
        wl.listen(proxy, self._on_event)

    def _on_event(self, opcode: int, args: Any) -> None:
        if opcode == 0:  # failed(cause, msg)
            _log.warning("EDR: Wayland image description failed: %s", args[1].s.decode())
            self.ready = False
        elif self.ready is None:  # ready / ready2
            if self._read_info:
                info = self.wl.request(self.proxy, 1, None, interface="wp_image_description_info_v1")
                self.wl.listen(info, lambda op, a: self._on_info(info, op, a))
            else:
                self.ready = True

    def _on_info(self, info: int, opcode: int, args: Any) -> None:
        signature = _COLOR_MANAGEMENT_V1["wp_image_description_info_v1"][1].split()[opcode].split(":")
        if opcode == 0:  # done is a destructor event
            self.wl.forget(info)
            self.wl.lib.wl_proxy_destroy(info)
            self.ready = True
        elif "h" not in signature[1]:
            self.info[signature[0]] = tuple(args[i].u for i in range(len(signature[1])))

    def wait(self) -> bool:
        while self.ready is None:
            self.wl.roundtrip()
        return self.ready

    def destroy(self) -> None:
        self.wl.forget(self.proxy)
        self.wl.request(self.proxy, 0, destroy=True)


class WaylandEdr:
    """Float EGL surface plus color-management tagging for raylib's Wayland window."""


    def __init__(self) -> None:
        self.path, self.raylib = _raylib_library()
        self.raylib.glfwGetPlatform.restype = C.c_int
        self.raylib.glfwGetWaylandDisplay.restype = C.c_void_p
        self.raylib.glfwGetWaylandWindow.restype = C.c_void_p
        self.raylib.glfwGetWaylandWindow.argtypes = [C.c_void_p]
        self.wl: _Wayland | None = None
        self.surface = 0
        self.manager = 0
        self.color_surface = 0
        self.feedback = 0
        self.description: _ImageDescription | None = None
        self.attached = False
        self.supported = False
        self.requested: bool | None = None
        self.headroom = 1.0
        # The preferred description's black and reference white, in cd/m².
        self.black = 0.0
        self.reference = 80.0
        self.preferred_stale = False
        self._callbacks: list[Any] = []

    @contextmanager
    def float_pixel_format(self) -> Iterator[None]:
        info = _Dl_info()
        libc = C.CDLL(None)
        libc.dladdr.argtypes = [C.c_void_p, C.POINTER(_Dl_info)]
        libc.dladdr(_address(self.raylib.glfwGetPlatform), C.byref(info))
        try:
            slot = _GotSlot(self.path, int(info.dli_fbase), "dlsym")
        except (LookupError, OSError, ValueError):
            _log.warning("EDR: raylib's dlsym import not found; using SDR", exc_info=True)
            yield
            return

        @_DLSYM
        def dlsym(handle: int, name: bytes) -> int:
            address = real_dlsym(handle, name)
            if name != b"eglGetConfigs" or not address:
                return address
            get_attrib = _EGL_GET_CONFIG_ATTRIB(real_dlsym(handle, b"eglGetConfigAttrib"))
            query_string = _EGL_QUERY_STRING(real_dlsym(handle, b"eglQueryString"))
            float_configs = self._deep_configs(_EGL_GET_CONFIGS(address), get_attrib, query_string)
            self._callbacks.append(float_configs)
            return _address(float_configs)

        if C.c_void_p.from_address(slot.address).value != _address(libc.dlsym):
            _log.warning("EDR: raylib's dlsym import is not bound to libc's dlsym; using SDR")
            yield
            return
        with ExitStack() as stack:
            try:
                original = stack.enter_context(slot.replaced(_address(dlsym)))
            except OSError:
                _log.warning("EDR: raylib's dlsym import could not be patched; using SDR", exc_info=True)
                yield
                return
            real_dlsym = _DLSYM(original)
            yield

    def _deep_configs(self, get_configs: Any, get_attrib: Any, query_string: Any) -> Any:
        """eglGetConfigs narrowed to window-capable RGBA16F configs, else 10-bit ones, else left unchanged."""

        def attrib(display: int, config: int, name: int) -> int:
            value = C.c_int()
            return value.value if get_attrib(display, config, name, C.byref(value)) else 0

        @_EGL_GET_CONFIGS
        def eglGetConfigs(display: int, configs: Any, size: int, count: Any) -> int:
            total = C.c_int()
            if not get_configs(display, None, 0, C.byref(total)):
                return 0
            native = (C.c_void_p * total.value)()
            get_configs(display, native, total.value, C.byref(total))
            # GLFW drops configs with alpha on Wayland unless the surface can be presented opaque.
            opaque = b"EGL_EXT_present_opaque" in (query_string(display, _EGL_EXTENSIONS) or b"").split()
            usable = [
                config for config in native
                if attrib(display, config, _EGL_SURFACE_TYPE) & _EGL_WINDOW_BIT
                and attrib(display, config, _EGL_RENDERABLE_TYPE) & _EGL_OPENGL_BIT
                and (opaque or attrib(display, config, _EGL_ALPHA_SIZE) == 0)
            ]
            floats = [config for config in usable if attrib(display, config, _EGL_RED_SIZE) == 16
                      and attrib(display, config, _EGL_COLOR_COMPONENT_TYPE_EXT) == _EGL_COLOR_COMPONENT_TYPE_FLOAT_EXT]
            ten_bit = [config for config in usable if attrib(display, config, _EGL_RED_SIZE) == 10]
            chosen = floats or ten_bit or list(native)
            if configs:
                for i, config in enumerate(chosen[:size]):
                    configs[i] = config
                count[0] = min(size, len(chosen))
            else:
                count[0] = len(chosen)
            return 1

        return eglGetConfigs

    def attach(self) -> None:
        self.supported = False
        if self.raylib.glfwGetPlatform() != rd.GLFW_PLATFORM_WAYLAND:
            return
        is_float, red_bits = backbuffer_format()
        if not is_float and red_bits < 10:
            _log.warning("EDR: Wayland window surface has %d-bit color; using SDR", red_bits)
            return
        self.wl = wl = _Wayland(self.raylib.glfwGetWaylandDisplay())
        # raylib's get_window_handle() points at its X11 handle storage even on Wayland; ask GLFW directly.
        self.surface = self.raylib.glfwGetWaylandWindow(int(ffi.cast("uintptr_t", rl.glfw_get_current_context()))) or 0
        self.manager = wl.bind_global("wp_color_manager_v1", 1) or 0
        if not self.manager:
            _log.warning("EDR: compositor has no wp_color_manager_v1; using SDR")
            return
        supported: dict[int, set[int]] = {0: set(), 1: set(), 2: set(), 3: set()}
        wl.listen(self.manager, lambda opcode, args: supported[opcode].add(args[0].u) if opcode < 4 else None)
        wl.roundtrip()
        intents, features, tfs, primaries = (supported[i] for i in range(4))
        missing = [
            label for label, ok in (
                ("parametric", _FEATURE_PARAMETRIC in features),
                ("set_luminances", _FEATURE_SET_LUMINANCES in features),
                ("gamma22", _TF_GAMMA22 in tfs),
                ("srgb primaries", _PRIMARIES_SRGB in primaries),
                ("perceptual intent", _INTENT_PERCEPTUAL in intents),
            ) if not ok
        ]
        if missing:
            _log.warning("EDR: compositor color management lacks %s; using SDR", ", ".join(missing))
            return
        self.feedback = wl.request(self.manager, 3, None, self.surface,
                                   interface="wp_color_management_surface_feedback_v1")
        wl.listen(self.feedback, self._on_preferred_changed)
        self.color_surface = wl.request(self.manager, 2, None, self.surface,
                                        interface="wp_color_management_surface_v1")
        self.supported = self._describe()

    def _on_preferred_changed(self, _opcode: int, _args: Any) -> None:
        # Moving to another output or toggling its HDR mode changes the preferred description.
        self.preferred_stale = True

    def _describe(self) -> bool:
        """Read the compositor's preferred description and build ours, anchored at its reference white."""
        wl = self.wl
        assert wl is not None
        preferred = _ImageDescription(
            wl, wl.request(self.feedback, 2, None, interface="wp_image_description_v1"), read_info=True)
        ok = preferred.wait()
        info = preferred.info
        preferred.destroy()
        if not ok or "luminances" not in info:
            return False
        min_lum, max_lum, reference = info["luminances"]
        target_max = info.get("target_luminance", (min_lum, max_lum))[1]
        self.headroom = max(1.0, target_max / reference) if reference > 0 and math.isfinite(target_max) else 1.0
        self.black, self.reference = min_lum / 10000, reference
        creator = wl.request(self.manager, 5, None, interface="wp_image_description_creator_params_v1")
        wl.request(creator, 1, _TF_GAMMA22)
        wl.request(creator, 3, _PRIMARIES_SRGB)
        wl.request(creator, 5, min_lum, max(target_max, reference), reference)
        description = _ImageDescription(
            wl, wl.request(creator, 0, None, interface="wp_image_description_v1", destroy=True), read_info=False)
        if not description.wait():
            description.destroy()
            return False
        if self.description is not None:
            self.description.destroy()
        self.description = description
        self.preferred_stale = False
        if self.requested:
            self._apply(True)
        return True

    def _apply(self, active: bool) -> None:
        wl = self.wl
        assert wl is not None
        # Double-buffered surface state: the next eglSwapBuffers commit applies it with the matching pixels.
        if active:
            assert self.description is not None
            wl.request(self.color_surface, 1, self.description.proxy, _INTENT_PERCEPTUAL)
        else:
            wl.request(self.color_surface, 2)
        wl.flush()

    def output_gain(self, headroom: float) -> float:
        # Gamma 2.2 maps signal E to black + (peak - black) * E**2.2, with the peak `headroom` times the reference
        # white; this gain puts the frame's 1.0 on the reference white.
        return ((self.reference - self.black) / (self.reference * headroom - self.black)) ** (1 / 2.2)

    def close(self) -> None:
        """Release the protocol objects before GLFW disconnects its display."""
        wl = self.wl
        if wl is None:
            return
        if self.description is not None:
            self.description.destroy()
        for proxy in (self.color_surface, self.feedback, self.manager):
            if proxy:
                wl.forget(proxy)
                wl.request(proxy, 0, destroy=True)
        wl.flush()
        wl.close()
        self.wl, self.description, self.supported = None, None, False
        self.color_surface = self.feedback = self.manager = 0

    def update(self, requested: bool) -> tuple[bool, float]:
        if not self.attached:
            self.attached = True
            self.attach()
        if not self.supported or self.wl is None:
            return False, 1.0
        self.wl.dispatch_pending()
        if self.preferred_stale and not self._describe():
            # The old description would still apply to the SDR frames that follow.
            if self.requested:
                self._apply(False)
            self.supported, self.requested = False, False
            return False, 1.0
        if requested != self.requested:
            self._apply(requested)
            self.requested = requested
        return (True, self.headroom) if requested else (False, 1.0)
