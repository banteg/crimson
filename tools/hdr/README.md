# HDR presentation investigation (#852)

Investigation date: 2026-10-23. Original investigation baseline:
`b5dfe1571afb79b1e536b333ef26a381f23ecaec`.

## Recommendation

Keep the RTX OpenGL renderer. First try an **opt-in Windows float WGL
backbuffer in a custom raylib/GLFW build**, paired with a final, whole-frame
linear-scRGB encoding pass and live Windows display queries. Do not enable it
by default until physical-display tests pass. Linux native Wayland HDR is
implemented in [#865](https://github.com/banteg/crimson/pull/865) using deep EGL
surfaces and color-management-v1, and has passed the physical-display checks
below on an Intel Arc / GNOME stack. Keep X11/Xwayland on SDR unless a separately validated presentation
route is selected. The Windows GLFW patch is not a Linux HDR solution.

This contribution provides a runnable framebuffer diagnostic and an integration
plan, not Windows/Linux HDR support. No production rendering code is changed.

## What the original baseline implied

- `src/grim/edr.py`: float offscreen allocation is portable; window setup,
  activation, and headroom querying are Cocoa-only.
- `src/grim/app.py:run_view`: creation reservation happens around `init_window`;
  live activation runs before drawing and after the borderless toggle.
- `src/crimson/render/rtx/hdr.py`: the shoulder uses
  `pow(headroom, 1/2.2)` because the legacy pipeline is approximately gamma
  encoded. Passing Windows scRGB values straight through this shader is wrong.
- `src/grim/texture_mode.py`: any SDR ancestor correctly forces headroom 1.
- `src/grim/canvas.py`: chooses float targets while EDR is active and forces
  classic through RGBA8 on a reserved float window. Preserve this behavior.
- `src/crimson/game/loop_view.py`: the gamma pass is another enclosing target.
  A Windows/Linux output conversion must happen **after** gamma, letterboxing,
  and UI, exactly once. Putting it in `HdrRenderer.scope` converts only the
  world; the HUD and later blending would remain in the wrong encoding.
- `src/grim/render_pipeline.py`: `RaylibDrawScope.draw` calls `end_drawing`,
  which already swaps through raylib. Adding a DXGI/Vulkan `WindowSink.present`
  alone would present twice; split raylib drawing/flush from swapping first.

## Presentation choices

| Route | Required work | Assessment |
| --- | --- | --- |
| Stock raylib/GLFW OpenGL | Existing SDR window, HDR offscreen FBOs | Windows remains SDR; Linux Wayland implementation in #865 |
| Windows float WGL | GLFW pixel-format selection change; raylib creation hint; rebuilt Python wheel; display queries; final encoding | Smallest renderer disruption; driver-dependent experiment |
| Windows D3D11/DXGI presenter | FP16 flip swapchain, explicit scRGB color space, GL/D3D sharing + synchronization, resize/device-loss handling | More explicit presentation control; retain world shaders; larger native bridge |
| Linux Wayland/EGL | Float EGLConfig, explicit surface color description, feedback/events, compositor and buffer-format support | Smallest plausible native Linux path; validate actual driver/compositor combinations |
| Vulkan presenter | Enumerate actual surface format/color-space pairs, swapchain recreation; GL/Vulkan memory + semaphore interop | Keep world renderer but considerably larger presentation boundary |
| SDL3 / SDL GPU | New window/input/presentation integration; renderer migration or interop | Useful reference and long-term option, not a drop-in HDR flag for raylib's GL renderer |
| Direct DRM/KMS | Own display modes, color properties, metadata, scanout and session permissions | Dedicated fullscreen appliance path; poor fit for ordinary desktop windows |

### Windows: GLFW #1907 is usable as a prototype, not a shipped API

Upstream GLFW still rejects WGL pixel formats other than `WGL_TYPE_RGBA_ARB` in
`src/wgl_context.c`. Merely asking for 16 channel bits cannot bypass that.
The proposal in [GLFW #1907](https://github.com/glfw/glfw/issues/1907) adds a float
type field, filters format selection by it, and accepts
`WGL_TYPE_RGBA_FLOAT_ARB`. Its `GLFW_FLOAT_PIXEL_TYPE` constant is a proposed
fork API, **not** an upstream hint that can be passed to the stock wheel.

Rebase against the GLFW actually compiled into the raylib dependency, not an
unrelated system GLFW. Add an explicit raylib creation option (or a small
native bridge before its internal `glfwCreateWindow`) rather than attempting
to change the pixel format after `InitWindow`. WGL pixel format is fixed for
that window. Request RGBA16F, verify WGL float support and the selected format,
and independently query the real default GL attachment type/bits. Retry an
ordinary SDR window when creation fails, before any game GL resources exist.
The old patch makes float a hard constraint; it does not supply this retry.
Avoid process-wide API detours analogous to the Cocoa interception.

The issue contains successful user reports and driver caveats; those are
upstream reports, not tests performed here. Its latest linked alternative,
[rrtt217/glfw #1](https://github.com/rrtt217/glfw/pull/1), merged into that fork
on 2026-04-03. It uses `WGL_NV_DX_interop2` and exposes a swapchain texture via
`glfwGetWindowSwapchainImageTexture`; it explicitly cannot transparently
replace framebuffer 0. Evaluate it if WGL fails on target GPUs. Do not assume
an extension containing `NV` is available on every vendor or adapter pairing.

For an explicit DXGI path use `R16G16B16A16_FLOAT` and
`DXGI_COLOR_SPACE_RGB_FULL_G10_NONE_P709`, check
`CheckColorSpaceSupport`/`SetColorSpace1`, and handle resize, adapter changes,
interop locks, and device removal. PQ/BT.2020 is an alternative encoding,
not what the current shader emits. Setting HDR10 metadata alone does not
create an HDR presentation path.

Detection must combine independent conditions:

1. The actual window surface is float and preserves extended values.
2. Identify the window's current monitor (`MonitorFromWindow`), map it to the
   active display path/target via `QueryDisplayConfig`, and query current HDR
   state. Do not confuse Advanced Color/WCG support with HDR being enabled.
   Prefer current HDR-specific DisplayConfig queries where available; use
   `IDXGIOutput6::GetDesc1` current color space as an older-system cross-check.
3. Query that target's `DISPLAYCONFIG_SDR_WHITE_LEVEL` and valid luminance
   capabilities (`DXGI_OUTPUT_DESC1`). Requery after output/settings changes;
   DXGI factories/output descriptions may need refreshing.
4. Any missing/failed/invalid query disables HDR, not a guessed headroom.

Windows scRGB uses linear BT.709 values: `1 = 80 nits`. The Windows structure's
`SDRWhiteLevel` is **80-nit multiples times 1000**, so `white_scale = value/1000`,
`paper_white_nits = 80*white_scale`, and
`headroom = max(1, peak_nits/paper_white_nits)` with finite/positive checks.
A value of 2000 means 160 nits, not 2 nits or 2000 nits. Peak luminance is a
capability/tonemapping bound, not proof of measured panel brightness.

Render the existing world/UI into a display-relative float canvas, preserving
classic's intermediate RGBA8 saturation. For an initial compatibility
experiment, decode the legacy approximate gamma-2.2 RGB at the **outermost**
pass (`pow(max(rgb,0),2.2)`) then multiply by `white_scale`; leave framebuffer
sRGB conversion disabled for linear scRGB. This approximate decode preserves
the current art convention; it is not an assertion that all assets are
colorimetrically calibrated. A later fully linear lighting pipeline is a
separate change. On an HDR-disabled float surface, still encode SDR content
according to that surface's defined color space; simply switching to the old
raw gamma-encoded writes would be incorrect. Recreate an ordinary surface if
its SDR behavior cannot be established reliably.

### Linux: negotiate content and buffers, not just monitor bit depth

Native Wayland is the first target. The
[color-management-v1 protocol](https://wayland.app/protocols/color-management-v1)
provides surface image descriptions and preferred-description feedback. Bind
only advertised versions/features/intents, wait for description `ready`, and
handle `failed` without issuing unsupported requests (protocol errors can kill
the connection). `windows_scrgb`, when advertised, provides an extended-linear
BT.709/80-nit description. Alternatively negotiate a supported parametric
description, including luminance/reference white, rather than guessing.
A preferred image description is a hint, not a guarantee that HDR is active;
use its color-volume/luminance information and actual platform feedback to
decide whether useful headroom exists. Do not assume Windows' SDR-white API
or scale exists on Linux.

The EGL side needs a window-capable float configuration
(`EGL_EXT_pixel_format_float`, 16-bit components), a corresponding buffer
format the driver/compositor accepts, and matching color-space handling.
[EGL_EXT_gl_colorspace_scrgb_linear](https://registry.khronos.org/EGL/extensions/EXT/EGL_EXT_gl_colorspace_scrgb_linear.txt)
defines the encoding but its presence alone does not prove a Wayland surface
is tagged or displayed correctly. Inspect the chosen EGL/Mesa implementation;
coordinate ownership so GLFW/EGL and a custom Wayland bridge do not both
create a color-management object for the same surface. Prefer a small native
GLFW/EGL integration over a second Python Wayland connection that cannot own
the existing `wl_surface`. The pbuffer prototype below is deliberately not
this window implementation.

Requery on surface preferred-description changes and output enter/leave;
recreate size/format-dependent resources when necessary. A compositor can map
one window to several outputs; follow surface feedback instead of choosing an
arbitrary output's EDID. Compositor HDR configuration, driver buffer support,
and a real HDR output are all necessary. Unsupported protocol, description,
float window config, compositor, or display state => SDR with a diagnostic
reason. Current X11/Xwayland stock-window support is not established by an
HDR desktop or by an FP16 GLX/FBO allocation; keep SDR by default. Specialized
compositor/Vulkan routes require separate explicit verification.

For Vulkan, enumerate `vkGetPhysicalDeviceSurfaceFormatsKHR` for the actual
surface and choose a supported format/color-space pair (e.g. FP16 +
`VK_COLOR_SPACE_EXTENDED_SRGB_LINEAR_EXT`, or 10-bit + HDR10 ST2084). An enum
being defined or `VK_EXT_hdr_metadata` existing is not sufficient. Exporting
GL images to Vulkan requires compatible memory handles, adapters and explicit
synchronization; CPU readback/upload is a diagnostic fallback, not a desirable
high-resolution game presenter.

## Proposed capability and fallback contract

#865 replaces the platform-named entry points with a shared facade. For future
adapters, especially Windows, consider extending it to report
`surface_encoding`, `surface_float`, `hdr_enabled`, `sdr_white_scale`,
`headroom`, `display_identity`, and `fallback_reason`. Keep reservation separate
from activation. macOS retains its current EDR behavior; unavailable adapters
retain the existing SDR path. Refresh before a frame, then use one immutable
snapshot through all canvas/gamma/output passes. Runtime failures return to
SDR at a frame boundary and rebuild target formats as needed. Keep an explicit
SDR override. No OS settings should be toggled by the game.

Prefer borderless fullscreen, matching today's `toggle_borderless_windowed`.
Treat exclusive fullscreen as a separate presentation mode requiring its own
validation. Monitor changes do not necessarily require window recreation;
only recreate when the presentation API/format requires it.

## Runnable diagnostic and results

`probe.py` has two modes:

```sh
# Standard library only; Linux EGL/Mesa required. No display involved.
python tools/hdr/probe.py --headless-egl

# In the project's installed Python environment, from repository root:
PYTHONPATH=src python tools/hdr/probe.py
```

The window mode uses the current application setup, displays numeric linear
patches, reads the actual default framebuffer before swap, and logs changes
when resized, moved between monitors, or toggled borderless with F11. It uses
the shared `float_backbuffer` / `activate_edr_window` setup, including Wayland
negotiation where supported. Its raw clears bypass the application canvas
encoding pass, so patch brightness is not calibrated; do not use it as a visual
HDR pass/fail test. The original revision was tested on a real Wayland desktop
as described below.

Executed here: Linux container, no DISPLAY/WAYLAND_DISPLAY or GPU device,
Mesa 25.2.8, llvmpipe LLVM 20.1.2, OpenGL 4.5. `headless-result.jsonl` records:

| Surface | Component type / red bits | Readback for 0.25, 1, 2, 4 |
| --- | --- | --- |
| EGL fixed pbuffer | GL_UNSIGNED_NORMALIZED / 8 | ~0.251, 1, 1, 1 |
| EGL float pbuffer | GL_FLOAT / 16 | 0.25, 1, 2, 4 |

Both runs check all RGB samples and GL errors and exit nonzero on mismatch.
`physical_hdr_verified` is always false: the probe cannot verify this.
This is a positive/negative control demonstrating why float readback alone
cannot detect HDR presentation, even for a default framebuffer.

## Physical-display validation (2026-10-23)

Fedora 44, native GNOME/Mutter 50.6 Wayland, Intel Arc (MTL), Mesa 26.2.5,
OpenGL 4.6, Samsung S27B80P at 3840x2160 60 Hz with 150% scaling.

The original diagnostic revision `0fa550ea7`, with master `90c492ed6`, completed
80 frames, two F11 borderless cycles and a resize without GL errors. Its 8-bit
window correctly clamped extended values to 1. Native window size returned to
960x360 after each cycle, then resized to 800x400. Renderbuffer dimensions
changed with DPI; that was not native window growth. This validates the probe
and SDR negative control, not physical HDR output.

Separately, #865's application pipeline selected a real FP16 backbuffer and
negotiated color-management without forced headroom. The user observed brighter
2x/4x/8x highlights with stable reference white across HDR/SDR alternation.
All 42 numeric capture states matched expected encoding. Resize, repeated
fullscreen cycles, desktop HDR off/on, and real X11 SDR fallback passed. An
actual RTX replay with simulated smoke ran for 75 seconds and exited normally;
the user confirmed correct scene, effects and HUD. Five GPU captures were
finite and error-free, with maximum float canvas RGB 2.1328125. All 21 focused
automated checks passed.

These are visual observations and framebuffer/protocol measurements, not
metered luminance/color calibration. The compositor's 10000-nit target is a
theoretical color-volume target, not measured panel brightness. Mixed HDR/SDR
monitor moves, mixed-output spanning, hotplug, sleep/resume, and other real
compositor/driver combinations remain follow-up coverage. Windows HDR is still
unimplemented and tracked in #852.

## Validation before enabling a native adapter

Automatable on a graphics runner: real window attachment type/bits and
extended-value readback; full world -> shockwave -> gamma -> canvas -> output
chain; UI white conversion; SDR override; float creation failure/retry; invalid
and stale display queries; target replacement; classic/RTX toggles; cleanup.
Extend `tests/render/test_edr_window.py`, keeping injected-headroom checks
explicitly separate from physical output. Existing macOS tests are not evidence
for Windows/Linux. Headless EGL is not evidence for any desktop session.

Real HDR hardware, per OS/GPU/driver/display/compositor combination:

- Windowed <-> borderless, plus exclusive fullscreen only if implemented.
- Move HDR -> SDR -> HDR, span mixed outputs, disconnect/reconnect display,
  change primary output, sleep/resume, minimize/restore, and change DPI/size.
- Toggle OS HDR and SDR brightness while running; test invalidated display
  identities and fallback/recovery without restart or stale bright frames.
- Toggle classic <-> RTX, gamma gain, letterboxing, HUD and screenshots.
  Screenshots/readback are not evidence that physical highlights exceed white.
- Use a calibrated scene with reference-white and 2x/4x highlight patches,
  several patch sizes, correct nits scale and peak bounds. Confirm physical
  luminance above SDR white with a meter where possible; record visual-only
  observations as such. Check double gamma, clipping, UI brightness drift,
  color casts and display automatic brightness limiting.
- Record OS/build, native Wayland vs Xwayland/X11, compositor/version, GPU and
  driver, display model, connection, HDR setting, white scale, output peak,
  negotiated surface format/encoding, and the diagnostic report. Test each
  Windows vendor and hybrid-GPU configuration rather than extrapolating.

## Primary references

- [Crimson #852](https://github.com/banteg/crimson/issues/852)
- [GLFW #1907](https://github.com/glfw/glfw/issues/1907) and
  [#890](https://github.com/glfw/glfw/issues/890) (both open when checked).
- [GLFW WGL selection](https://github.com/glfw/glfw/blob/master/src/wgl_context.c)
- [Windows Advanced Color](https://learn.microsoft.com/en-us/windows/win32/direct3darticles/high-dynamic-range)
- [Windows SDR white units](https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-displayconfig_sdr_white_level)
- [DXGI output description](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_6/ns-dxgi1_6-dxgi_output_desc1)
- [DXGI interop GLFW fork](https://github.com/rrtt217/glfw/pull/1)
- [Wayland color management](https://wayland.app/protocols/color-management-v1)
- [EGL linear scRGB specification](https://registry.khronos.org/EGL/extensions/EXT/EGL_EXT_gl_colorspace_scrgb_linear.txt)
- [Vulkan swapchain color spaces](https://docs.vulkan.org/refpages/latest/refpages/source/VK_EXT_swapchain_colorspace.html)
- [SDL renderer HDR properties](https://wiki.libsdl.org/SDL3/SDL_GetRendererProperties)
