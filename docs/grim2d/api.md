---
tags:
  - status-analysis
---

# Grim2D API vtable (draft)

This is a first-pass extraction of the Grim2D API vtable usage from the
classic `crimsonland.exe` decompilation. The engine interface pointer is
`DAT_0048083c` in `analysis/ghidra/raw/crimsonland.exe_decompiled.c`.

The interface is created in `GRIM__GetInterface` (`grim.dll`), which sets the
object vtable to `PTR_LAB_1004c238` (address `0x1004c238` in the DLL).

We created functions at vtable entry addresses via
`analysis/ghidra/scripts/CreateGrim2DVtableFunctions.java` and re-exported
`grim.dll_functions.json` to capture those entry names. The latest vtable JSON
exports now include 84 entry points created from the vtable.

For a high-level summary, see [Grim2D overview](index.md).

## Extraction artifact

We extracted all `(*DAT_0048083c + offset)` callsites and wrote them to:

- `analysis/ghidra/derived/grim2d_vtable_calls.json`
- `analysis/ghidra/derived/grim2d_vtable_callsites.json` (full callsite index with line numbers)


The JSON includes offset, callsite count, unique functions, and sample lines.

We also dumped the Grim2D vtable itself from `game_bins/crimsonland/1.9.93-gog/grim.dll` and joined the
two datasets:

- `analysis/ghidra/derived/grim2d_vtable_entries.json`
- `analysis/ghidra/derived/grim2d_vtable_map.json`


The map JSON includes function size, calling convention, return type, parameter
count, and the raw Ghidra signature for faster triage.

We now filter vtable exports to entries that resolve into the `.text` section
(84 entries / 0x150 bytes). Values after `0x14c` in the raw table look like
data, not executable pointers.

We also generate an evidence appendix with callsite snippets:

- [Grim2D API evidence](api-evidence.md)


## Internal helpers (non-vtable)

- `grim_convert_vertex_space` (`0x10016944`) remaps vec4 coordinates between three space
  modes used by the batcher. Modes 1/2/3 control whether xyz and w are in `[-1, 1]`
  or `[0, 1]`; see the evidence appendix for inferred mappings.

- `grim_pixel_format_init` (`0x100170f9`) initializes format descriptors and palette
  expansion; it also stores the coordinate mode later compared against the current
  mode before converting vertices.

- `grim_config_dialog_proc` (`0x10002120`) handles the Grim2D config dialog messages.
- `grim_window_create` (`0x10002680`) registers the window class and creates the main window.
- `grim_window_destroy` (`0x10002880`) posts quit and destroys the main window.
- `grim_d3d_init` (`0x10003e60`) creates the Direct3D8 interface and sets up the device.
- `grim_keyboard_init` (`0x1000a390`) / `grim_keyboard_poll` (`0x1000a4a0`) / `grim_keyboard_shutdown`
  (`0x1000a550`) manage the DirectInput keyboard device. Initialization installs the keyboard
  data format, foreground/nonexclusive cooperative mode, and a ten-event buffer. The poll retries acquisition only for
  lost/not-acquired errors, snapshots all 256 key bytes, then overlays up to ten buffered events.
  Shutdown unacquires/releases the device before releasing the parent DirectInput interface.

- `grim_mouse_init` (`0x1000a5a0`) / `grim_mouse_poll` (`0x1000a670`) / `grim_mouse_shutdown`
  (`0x1000a7d0`) manage the DirectInput mouse device. Initialization installs the Mouse2
  data format and cooperative flags 5 before acquiring and polling. Each poll drains up to 101
  relative-motion samples into the frame deltas, cumulative XY position, and cumulative wheel
  position; failed state reads reacquire while DirectInput reports input loss. Shutdown mirrors
  the keyboard path: unacquire/release the device, then release the parent DirectInput interface.

- `grim_joystick_up_active` (`0x10006ea0`) through
  `grim_joystick_right_active` (`0x10006f90`) compare centered X/Y axis values
  against the configured deadzone using strict inequalities.

- `grim_joystick_enum_device` (`0x1000a110`) / `grim_joystick_configure_axis`
  (`0x1000a150`) / `grim_joystick_init` (`0x1000a1c0`) /
  `grim_joystick_poll` (`0x1000a2b0`) / `grim_joystick_shutdown`
  (`0x1000a330`) exactly recover the DirectInput joystick lifecycle.
  Initialization selects the first attached game controller, installs the
  Joystick2 format, applies a `[-1000, 1000]` range to each axis, and acquires
  it. Polling retries lost acquisition and snapshots all 272 state bytes;
  shutdown releases both COM objects.


## Top offsets by callsite count

These are the most frequently used offsets (likely the core draw/config calls).
Use them to prioritize runtime validation and signature cleanup.

| Offset | Name | Callsites | Unique funcs |
| --- | --- | --- | --- |
| `0x20` | `grim_set_config_var` | 206 | 35 |
| `0x114` | `grim_set_color` | 203 | 37 |
| `0x11c` | `grim_draw_quad` | 100 | 21 |
| `0xf0` | `grim_end_batch` | 86 | 28 |
| `0x148` | `grim_draw_text_small_fmt` | 86 | 15 |
| `0xe8` | `grim_begin_batch` | 79 | 23 |
| `0xc4` | `grim_bind_texture` | 66 | 22 |
| `0xfc` | `grim_set_rotation` | 65 | 17 |
| `0x100` | `grim_set_uv` | 59 | 23 |
| `0x48` | `grim_was_key_pressed` | 39 | 16 |
| `0x104` | `grim_set_atlas_frame` | 25 | 6 |
| `0xd0` | `grim_draw_rect_filled` | 24 | 14 |
| `0xc0` | `grim_get_texture_handle` | 22 | 8 |
| `0x110` | `grim_set_color_ptr` | 20 | 10 |
| `0x144` | `grim_draw_text_small` | 20 | 9 |
| `0x24` | `grim_get_config_var` | 17 | 4 |
| `0x14c` | `grim_measure_text_width` | 14 | 10 |
| `0xd4` | `grim_draw_rect_outline` | 12 | 11 |
| `0x4c` | `grim_flush_input` | 12 | 10 |
| `0x118` | `grim_set_color_slot` | 12 | 2 |

Validation highlights (see the evidence appendix for snippets):

- `grim_set_config_var` callsites pass an ID plus a 16-byte config record by
  value. Many callsites initialize only its first word (for example ID `0x15`
  with value `2`), while richer IDs consume the remaining fields.

- `grim_get_config_var` is logically a 16-byte structure return. Callers push
  an ID and hidden result buffer, then consume the returned buffer pointer;
  invalid IDs receive the zero-filled default record.

- `grim_flush_input` zeroes the 256-byte keyboard state before and after
  draining 20-byte DirectInput8 events, then clears the buffered key-char FIFO.

- `grim_was_key_pressed` is both a press-edge and held-repeat query: the first
  event loads a 0.5-second cooldown and later repeats use 20% of that delay.

- `grim_was_mouse_button_pressed` reports `down && previously_released`, then
  refreshes its release latch from a second state query; cached mode preserves
  the same short-circuit behavior without polling DirectInput.

- `grim_get_key_char` pops an eight-int internal FIFO, while
  `grim_set_key_char_buffer` installs a separate caller-owned text buffer,
  count pointer, and capacity used by the window-message input path.

- `grim_bind_texture` is called with `(handle, 0)` and followed by `grim_set_uv` + `grim_draw_quad`,
  consistent with binding stage 0 before drawing.

- `grim_set_uv` receives literal `0/1` and atlas fractions (e.g. `0.0625`, `0.00390625`) before draws,
  confirming a 4-float UV rectangle.

- `grim_set_atlas_frame` uses atlas sizes `4/8/16` plus frame indices, while `grim_set_sub_rect` supplies
  width/height for multi-cell frames.

- `grim_set_sub_rect` shows explicit calls like `(8, 2, 1, frame<<1)` and is followed by `grim_draw_quad`,
  matching atlas grid sub-rect selection.

- `grim_begin_batch` / `grim_end_batch` bracket `grim_draw_quad` and `submit_*` calls in most UI paths.
- `grim_draw_quad_xy` is a thin wrapper around `grim_draw_quad` that forwards `xy[0]/xy[1]`.
- `grim_draw_text_small_fmt` calls `vsprintf` in grim.dll and forwards to `grim_draw_text_small`, so the
  varargs signature is correct.

- `grim_measure_text_width` returns an integer width used for layout/centering in menus.
- `grim_set_color` / `grim_set_color_slot` pass RGBA floats or float pointers that grim.dll packs into ARGB.
- `grim_submit_vertices_offset` appears as vtable offset `+ 300` (0x12c) in the decompiler and adds XY
  offsets to 7-float stride vertices before batching.

- `grim_draw_quad_points` emits four explicit points with current UV/color slots and batches immediately.
- `grim_draw_quad_rotated_matrix` builds four center-relative corners, applies the cached 2x2 rotation
  matrix, translates them back to the requested center, and emits the current UV/color slots.
- `grim_draw_line` builds a half-width vector then forwards to `grim_draw_line_quad`, which emits the quad
  via `grim_draw_quad_points`.

- `grim_draw_circle_filled` / `grim_draw_circle_outline` appear in gameplay effects with UV + color setup
  immediately before the draw calls.

- The timing helpers (`get_time_ms`, `set_time_ms`, `get_frame_dt`, `get_fps`) have no decompiled callsites yet;
  grim.dll stores a millisecond counter and clamps frame delta to `0.1`.

- `grim_apply_config` opens the Grim2D config dialog and initializes Direct3D8 before applying settings.
- `grim_apply_settings` is an exact-matched `bool` wrapper that enters
  `grim_run_loop`; despite the provisional name, slot `0x1c` owns the Win32
  message pump and Direct3D frame loop rather than a settings-only operation.
- `grim_init_system` initializes D3D and input devices, then loads `smallFnt.dat`.
- `grim_shutdown` exactly tears down the optional lookup blob, DirectInput
  devices, Direct3D resources, and the main window in that order.
- `grim_set_render_target` is invoked with render target handles and `-1` to restore the backbuffer.
- `grim_get_config_float` exactly maps six IDs to scaled joystick axes,
  `0x15f`/`0x160` to direct mouse X/Y delta, and two three-ID ranges to the
  indexed delta compatibility methods; unmatched IDs return zero.

- Vtable slot `0x0c`, previously labeled `grim_check_device`, is the
  exact-matched `grim_save_screenshot(char *path)`: it captures the front
  buffer and saves it as a BMP through `D3DXSaveSurfaceToFileA`.
- `grim_draw_fullscreen_color` only draws when alpha is positive and forces texture stage 0 to null.

## Grim state/config IDs (vtable `+0x20` / `grim_set_config_var`)

High-confidence IDs from the grim.dll switch body and recovered Grim2D SDK
state names (partial list):

| ID | Label (proposed) | Behavior (grim.dll) | Notes |
| --- | --- | --- | --- |
| `0x10` | `GRIM_CFG_RESOURCE_PAQ` | Stores a string path, validates with `FUN_10005a40`, updates config table | Used by `setresourcepaq` console command. |
| `0x12` | `GRIM_CFG_ALPHABLEND_ENABLE` | `SetRenderState(D3DRS_ALPHABLENDENABLE, value & 0xff)` | Toggles alpha blending. |
| `0x13` | `GRIM_CFG_SRC_BLEND` | `SetRenderState(D3DRS_SRCBLEND, value)` | UI uses `5` (SRCALPHA). |
| `0x14` | `GRIM_CFG_DEST_BLEND` | `SetRenderState(D3DRS_DESTBLEND, value)` | UI uses `6` (INVSRCALPHA). |
| `0x15` | `GRIM_CFG_TEX_FILTER` | `SetTextureStageState(MINFILTER/MAGFILTER, value)` | When `value==3`, sets anisotropy. |
| `0x18` | `GRIM_STATE_FONTSCALE` | Default path: stores value in config table | SDK `grSTATE_FONTSCALE`; called with float-like values (0.5, 1.0). |
| `0x1b` | `GRIM_CFG_TEXTURE_FACTOR` | `SetRenderState(D3DRS_TEXTUREFACTOR, packed RGB)` | Uses float→int conversions before packing. |
| `0x1c` | `GRIM_CFG_GAMMA_RAMP` | Builds `D3DGAMMARAMP` and calls `SetGammaRamp` | Triggered by `setGammaRamp`. |
| `0x29` | `GRIM_CFG_BACKBUFFER_WIDTH` | Sets `grim_backbuffer_width` | Mirrors config table. |
| `0x2a` | `GRIM_CFG_BACKBUFFER_HEIGHT` | Sets `grim_backbuffer_height` | Mirrors config table. |
| `0x2b` | `GRIM_CFG_TEXTURE_FORMAT` | Sets `grim_texture_format` based on `value` | Likely BPP/format selector. |
| `0x36` | `GRIM_CFG_PRESENT` | Calls `IDirect3DDevice8::Present` | Explicit present trigger. |
| `0x55` | `GRIM_CFG_RENDER_DISABLED` | Sets `grim_render_disabled` flag | Gates rendering. |

Other handled IDs exist (e.g., `0x5`, `0x6`, `0x7`, `0xb`, `0xc`, `0xd`, `0xe`, `0x1a`, `0x2d`, `0x34`, `0x42`, `0x52`) but their semantics remain unknown; they mostly write into the config tables and/or stash pointers for later use.


## Validation backlog

Offsets below have no callsites in `crimsonland.exe` or only a handful (1–3).
They are still part of the vtable, but most evidence is from `grim.dll` bodies.
Good targets for runtime validation or further callsite hunting.

Runtime validation notes live in `runtime-validation.md`.

### Zero callsites in `crimsonland.exe` (grim.dll-only evidence)

| Offset | Name | Signature |
| --- | --- | --- |
| `0x0` | `grim_release` | `void grim_release(void)` |
| `0x4` | `grim_set_paused` | `void grim_set_paused(int paused)` |
| `0x8` | `grim_get_version` | `float grim_get_version(void)` |
| `0xc` | `grim_save_screenshot` | `bool grim_save_screenshot(char *path)` |
| `0x34` | `grim_get_time_ms` | `int grim_get_time_ms(void)` |
| `0x38` | `grim_set_time_ms` | `void grim_set_time_ms(int ms)` |
| `0x3c` | `grim_get_frame_dt` | `float grim_get_frame_dt(void)` |
| `0x40` | `grim_get_fps` | `float grim_get_fps(void)` |
| `0x5c` | `grim_was_mouse_button_pressed` | `bool grim_was_mouse_button_pressed(int button)` |
| `0x64` | `grim_set_mouse_pos` | `void grim_set_mouse_pos(float x, float y)` |
| `0x68` | `grim_get_mouse_x` | `float grim_get_mouse_x(void)` |
| `0x6c` | `grim_get_mouse_y` | `float grim_get_mouse_y(void)` |
| `0x70` | `grim_get_mouse_dx` | `float grim_get_mouse_dx(void)` |
| `0x74` | `grim_get_mouse_dy` | `float grim_get_mouse_dy(void)` |
| `0x78` | `grim_get_mouse_dx_indexed` | `float grim_get_mouse_dx_indexed(int index)` |
| `0x7c` | `grim_get_mouse_dy_indexed` | `float grim_get_mouse_dy_indexed(int index)` |
| `0x88` | `grim_get_slot_float` | `float grim_get_slot_float(int index)` |
| `0x8c` | `grim_get_slot_int` | `int grim_get_slot_int(int index)` |
| `0x90` | `grim_set_slot_float` | `void grim_set_slot_float(int index, float value)` |
| `0x94` | `grim_set_slot_int` | `void grim_set_slot_int(int index, int value)` |
| `0x98` | `grim_get_joystick_x` | `int grim_get_joystick_x(void)` |
| `0x9c` | `grim_get_joystick_y` | `int grim_get_joystick_y(void)` |
| `0xa0` | `grim_get_joystick_z` | `int grim_get_joystick_z(void)` |
| `0xa8` | `grim_is_joystick_button_down` | `unsigned char grim_is_joystick_button_down(int button)` |
| `0xb0` | `grim_recreate_texture` | `unsigned char grim_recreate_texture(int handle)` |
| `0xb8` | `grim_save_texture` | `bool grim_save_texture(int handle, char *path)` |
| `0xbc` | `grim_destroy_texture` | `void grim_destroy_texture(int handle)` |
| `0xe0` | `grim_draw_line` | `void grim_draw_line(float * p0, float * p1, float thickness)` |
| `0xe4` | `grim_draw_line_quad` | `void grim_draw_line_quad(float * p0, float * p1, float * half_vec)` |
| `0xec` | `grim_flush_batch` | `void grim_flush_batch(void)` |
| `0xf4` | `grim_submit_vertex_raw` | `void grim_submit_vertex_raw(float * vertex)` |
| `0xf8` | `grim_submit_quad_raw` | `void grim_submit_quad_raw(float * verts)` |
| `0x124` | `grim_draw_quad_rotated_matrix` | `void grim_draw_quad_rotated_matrix(float x, float y, float w, float h)` |

### Low callsite offsets (1–3)

| Offset | Callsites | Name | Signature |
| --- | --- | --- | --- |
| `0x10` | 1 | `grim_apply_config` | `int grim_apply_config(void)` |
| `0x14` | 1 | `grim_init_system` | `int grim_init_system(void)` |
| `0x18` | 1 | `grim_shutdown` | `void grim_shutdown(void)` |
| `0x1c` | 1 | `grim_apply_settings` | `bool grim_apply_settings(void)` |
| `0x28` | 1 | `grim_get_error_text` | `char * grim_get_error_text(void)` |
| `0x50` | 1 | `grim_get_key_char` | `int grim_get_key_char(void)` |
| `0xac` | 1 | `grim_create_texture` | `unsigned char grim_create_texture(char * name, int width, int height)` |
| `0xc8` | 1 | `grim_draw_fullscreen_quad` | `void grim_draw_fullscreen_quad(int unused)` |
| `0xd8` | 1 | `grim_draw_circle_filled` | `void grim_draw_circle_filled(float x, float y, float radius)` |
| `0xdc` | 1 | `grim_draw_circle_outline` | `void grim_draw_circle_outline(float x, float y, float radius)` |
| `0x54` | 2 | `grim_set_key_char_buffer` | `void grim_set_key_char_buffer(uchar * buffer, int * count, int size)` |
| `0x60` | 2 | `grim_get_mouse_wheel_delta` | `float grim_get_mouse_wheel_delta(void)` |
| `0xa4` | 2 | `grim_get_joystick_pov` | `int grim_get_joystick_pov(int index)` |
| `0xcc` | 2 | `grim_draw_fullscreen_color` | `void grim_draw_fullscreen_color(float r, float g, float b, float a)` |
| `0xb4` | 3 | `grim_load_texture` | `unsigned char grim_load_texture(char * name, char * path)` |
| `0x130` | 3 | `grim_submit_vertices_offset_color` | `void grim_submit_vertices_offset_color(float *verts, int count, float *offset, const uint32_t *color)` |
| `0x140` | 3 | `grim_draw_text_mono_fmt` | `void grim_draw_text_mono_fmt(int * self, float x, float y, char * fmt)` |

## Input-ish offsets (evidence)

These offsets appear with keycodes or input-related values:

- `0x44` / `0x48` used with keycodes like `0x1d`, `0x9d`, `0xd0`, `200`
  in `console_update` (`FUN_00401a40`) (likely key down / key pressed checks).

- `0x50` is a zero-arg call in `console_input_poll` (`FUN_00401060`)
  (likely a per-frame poll).

- `0x58` / `0x80` appear in input handling loops in
  `input_primary_just_pressed` (`FUN_00446030`).

- `0x80` routes raw keys, five mouse buttons, twelve joystick buttons, four
  joystick directions, six thresholded axes, and three groups of five RIM
  actions. Its recovered byte-return ABI matches the direct forwarding paths.
- `0x84` maps six sparse IDs to scaled joystick axes, `0x15f`/`0x160` to
  direct mouse X/Y delta, and `0x163..0x165`/`0x168..0x16a` to the indexed
  delta compatibility methods; unmatched IDs return zero.

- `0x60`/`0x70`/`0x74` read the DirectInput mouse deltas, while
  `0x64`/`0x68`/`0x6c` update or return the accumulated mouse position.
  The `0x78`/`0x7c` indexed variants ignore the index and forward virtually to
  `0x70`/`0x74`; this is confirmed by exact VC6.5 matches rather than inferred
  only from the vtable layout.

- `0x88`..`0x94` are exact-matched unchecked accessors for independent
  float/int scratch arrays.
- `0x98`..`0xa0` return cached joystick axis values.


## Vtable map (high confidence)

| Offset | Name | Signature (guess) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `0x0` | `release` | `void release(void)` | high | vtable destructor (operator_delete) |
| `0x4` | `set_paused` | `void set_paused(int paused)` | high | sets global pause flag |
| `0x8` | `get_version` | `float get_version(void)` | high | returns constant 1.21 |
| `0xc` | `save_screenshot` | `bool save_screenshot(char *path)` | high | exact front-buffer capture and BMP save; original identifier unknown |
| `0x10` | `apply_config` | `bool apply_config(void)` | high | opens D3D config dialog and applies settings |
| `0x14` | `init_system` | `bool init_system(void)` | high | returns success before game starts |
| `0x18` | `shutdown` | `void shutdown(void)` | high | exact ordered teardown of lookup, input, Direct3D, and window resources |
| `0x1c` | `apply_settings` | `bool apply_settings(void)` | high | exact wrapper around the Win32/D3D run loop; public name remains provisional |
| `0x20` | `set_config_var` | `void set_config_var(uint32_t id, grim_config_value_t value)` | high | takes a 16-byte record by value; some IDs map to D3D render/texture stage state |
| `0x24` | `get_config_var` | `grim_config_value_t get_config_var(int id)` | high | returns a 4-dword record from the 128-entry config table, or a zero default |
| `0x28` | `get_error_text` | `const char * get_error_text(void)` | high | error string for MessageBox |
| `0x2c` | `clear_color` | `void clear_color(float r, float g, float b, float a)` | high | packs RGBA into device clear color |
| `0x30` | `set_render_target` | `int set_render_target(int target_index)` | high | switches render target surfaces; -1 restores backbuffer |
| `0x34` | `get_time_ms` | `int get_time_ms(void)` | high | frame time accumulator (ms) |
| `0x38` | `set_time_ms` | `void set_time_ms(int ms)` | high | overrides time accumulator |
| `0x3c` | `get_frame_dt` | `float get_frame_dt(void)` | high | clamped frame delta |
| `0x40` | `get_fps` | `float get_fps(void)` | high | frame rate estimate |
| `0x44` | `is_key_down` | `uint8_t is_key_down(uint32_t key)` | high | low-byte-indexed 0/1 keyboard-state query |
| `0x48` | `was_key_pressed` | `bool was_key_pressed(uint32_t key)` | high | press edge plus timed held repeats |
| `0x4c` | `flush_input` | `void flush_input(void)` | high | clears input buffers + drains DirectInput |
| `0x50` | `get_key_char` | `int get_key_char(void)` | high | console text input |
| `0x54` | `set_key_char_buffer` | `void set_key_char_buffer(uint8_t *buffer, int *count, int size)` | high | stores ring buffer pointers |
| `0x58` | `is_mouse_button_down` | `uint8_t is_mouse_button_down(int button)` | high | returns cached button state or polls input |
| `0x5c` | `was_mouse_button_pressed` | `bool was_mouse_button_pressed(int button)` | high | edge-triggered mouse button using cached state; no decompiled callsites yet |
| `0x60` | `get_mouse_wheel_delta` | `float get_mouse_wheel_delta(void)` | high | +/- wheel to change selection |
| `0x64` | `set_mouse_pos` | `void set_mouse_pos(float x, float y)` | high | updates cached mouse position |
| `0x68` | `get_mouse_x` | `float get_mouse_x(void)` | high | cached mouse position X |
| `0x6c` | `get_mouse_y` | `float get_mouse_y(void)` | high | cached mouse position Y |
| `0x70` | `get_mouse_dx` | `float get_mouse_dx(void)` | high | cached mouse delta X |
| `0x74` | `get_mouse_dy` | `float get_mouse_dy(void)` | high | cached mouse delta Y |
| `0x78` | `get_mouse_dx_indexed` | `float get_mouse_dx_indexed(int index)` | high | aliases mouse dx (calls 0x70); index unused |
| `0x7c` | `get_mouse_dy_indexed` | `float get_mouse_dy_indexed(int index)` | high | aliases mouse dy (calls 0x74); index unused |
| `0x80` | `is_key_active` | `uint8_t is_key_active(int key)` | high | routes raw keys plus mouse, joystick, axis, and RIM action IDs; natural VC6.5 source is a documented 73.93% WIP |
| `0x84` | `get_config_float` | `float get_config_float(int id)` | high | exactly matched router for six joystick axes and direct/indexed mouse deltas |
| `0x88` | `get_slot_float` | `float get_slot_float(int index)` | high | reads float slot array |
| `0x8c` | `get_slot_int` | `int get_slot_int(int index)` | high | reads int slot array |
| `0x90` | `set_slot_float` | `void set_slot_float(int index, float value)` | high | writes float slot array |
| `0x94` | `set_slot_int` | `void set_slot_int(int index, int value)` | high | writes int slot array |
| `0x98` | `get_joystick_x` | `int get_joystick_x(void)` | high | returns cached joystick X |
| `0x9c` | `get_joystick_y` | `int get_joystick_y(void)` | high | returns cached joystick Y |
| `0xa0` | `get_joystick_z` | `int get_joystick_z(void)` | high | returns cached joystick Z |
| `0xa4` | `get_joystick_pov` | `int get_joystick_pov(int index)` | high | returns cached POV value |
| `0xa8` | `is_joystick_button_down` | `uint8_t is_joystick_button_down(int button)` | high | returns bit 7 of the low-byte-indexed cached button |
| `0xac` | `create_texture` | `bool create_texture(const char *name, int width, int height)` | confirmed | exact-matched blank texture allocation in a free slot |
| `0xb0` | `recreate_texture` | `bool recreate_texture(int handle)` | confirmed | exact-matched managed texture recreation with success-only swap |
| `0xb4` | `load_texture` | `bool load_texture(const char *name, const char *path)` | confirmed | exact-matched `(name, filename)` wrapper |
| `0xb8` | `save_texture` | `bool save_texture(int handle, const char *path)` | confirmed | saves the texture as TGA through `D3DXSaveTextureToFileA` |
| `0xbc` | `destroy_texture` | `void destroy_texture(int handle)` | high | releases texture and clears slot |
| `0xc0` | `get_texture_handle` | `int get_texture_handle(const char *name)` | high | returns `-1` on missing |
| `0xc4` | `bind_texture` | `void bind_texture(int handle, int stage)` | high | validates handle then sets device texture stage |
| `0xc8` | `draw_fullscreen_quad` | `void draw_fullscreen_quad(int unused)` | confirmed | caller passes zero; batch draws current texture fullscreen |
| `0xcc` | `draw_fullscreen_color` | `void draw_fullscreen_color(float r, float g, float b, float a)` | high | alpha>0 draws a fullscreen color quad |
| `0xd0` | `draw_rect_filled` | `void draw_rect_filled(const float *xy, float w, float h, const float *rgba)` | confirmed | UI panel fill / background quad with explicit color |
| `0xd4` | `draw_rect_outline` | `void draw_rect_outline(const float *xy, float w, float h)` | high | UI panel outline/frame (4 edge quads) |
| `0xd8` | `draw_circle_filled` | `void draw_circle_filled(float x, float y, float radius)` | confirmed | exact-matched triangle fan; `int(radius * 0.125f + 12)` segments |
| `0xdc` | `draw_circle_outline` | `void draw_circle_outline(float x, float y, float radius)` | confirmed | exact-matched triangle strip; `int(radius * 0.2f + 14)` segments |
| `0xe0` | `draw_line` | `void draw_line(const float *p0, const float *p1, float thickness)` | confirmed | exact-matched local-static line-vector transform, then calls 0xe4 |
| `0xe4` | `draw_line_quad` | `void draw_line_quad(const float *p0, const float *p1, const float *half_vec)` | confirmed | exact-matched quad expansion from endpoints + half_vec |
| `0xec` | `flush_batch` | `void flush_batch(void)` | high | flushes batch when buffer fills |
| `0xe8` | `begin_batch` | `void begin_batch(void)` | high | start buffered quad batch |
| `0xf0` | `end_batch` | `void end_batch(void)` | high | flush buffered batch |
| `0xf4` | `submit_vertex_raw` | `void submit_vertex_raw(const float *vertex)` | confirmed | exact-matched 28-byte vertex append; lazy begin + auto-flush |
| `0xf8` | `submit_quad_raw` | `void submit_quad_raw(const float *verts)` | confirmed | exact-matched 112-byte quad append; auto-flush |
| `0xfc` | `set_rotation` | `void set_rotation(float radians)` | high | precomputes sin/cos (+45°) for rotation matrix |
| `0x100` | `set_uv` | `void set_uv(float u0, float v0, float u1, float v1)` | high | sets all 4 UV pairs (u0/v0/u1/v1) |
| `0x104` | `set_atlas_frame` | `void set_atlas_frame(int atlas_size, int frame)` | high | atlas size (cells per side) + frame index; extra args in decompiled callsites are ignored |
| `0x108` | `set_sub_rect` | `void set_sub_rect(int atlas_size, int width, int height, int frame)` | high | atlas grid sub-rect: `atlas_size` indexes the UV table (2/4/8/16), width/height in cells, `frame` selects top-left cell |
| `0x10c` | `set_uv_point` | `void set_uv_point(int index, float u, float v)` | high | sets a single UV pair (index 0..3) for custom quad UVs |
| `0x110` | `set_color_ptr` | `void set_color_ptr(const float *rgba)` | high | sets current color from float[4] (RGBA 0..1) |
| `0x114` | `set_color` | `void set_color(float r, float g, float b, float a)` | high | RGBA floats |
| `0x118` | `set_color_slot` | `void set_color_slot(int index, float r, float g, float b, float a)` | high | packs RGBA into color slot array (index 0..3, per-corner) |
| `0x11c` | `draw_quad` | `void draw_quad(float x, float y, float w, float h)` | high | core draw call; uses per-corner color slots + UV array |
| `0x120` | `draw_quad_xy` | `void draw_quad_xy(const float *xy, float w, float h)` | high | wrapper for draw_quad using `xy` pointer |
| `0x124` | `draw_quad_rotated_matrix` | `void draw_quad_rotated_matrix(float x, float y, float w, float h)` | confirmed | exact-matched centered 2x2 matrix transform with batched UV/color emission |
| `0x128` | `submit_vertices_transform` | `void submit_vertices_transform(const float *verts, int count, const float *offset, const float *matrix)` | high | copies `count` verts (7-float stride) then applies 2x2 matrix + offset |
| `0x12c` | `submit_vertices_offset` | `void submit_vertices_offset(const float *verts, int count, const float *offset)` | high | copies verts then offsets XY (7-float stride) |
| `0x130` | `submit_vertices_offset_color` | `void submit_vertices_offset_color(const float *verts, int count, const float *offset, const uint32_t *color)` | high | copies verts, offsets XY, overrides packed color from `*color` |
| `0x134` | `submit_vertices_transform_color` | `void submit_vertices_transform_color(const float *verts, int count, const float *offset, const float *matrix, const uint32_t *color)` | high | copies verts, applies matrix+offset, overrides packed color from `*color` |
| `0x138` | `draw_quad_points` | `void draw_quad_points(float x0, float y0, float x1, float y1, float x2, float y2, float x3, float y3)` | high | pushes quad from 4 points using current UV/color slots |
| `0x13c` | `draw_text_mono` | `void draw_text_mono(float x, float y, const char *text)` | high | fixed 16px grid; handles a few extended codes; binds Grim2D font texture (resource `0x6f`) |
| `0x140` | `draw_text_mono_fmt` | `void draw_text_mono_fmt(float x, float y, const char *fmt, ...)` | high | printf-style wrapper around `draw_text_mono` |
| `0x144` | `draw_text_small` | `void draw_text_small(float x, float y, char *text)` | confirmed | exact-matched batched `GRIM_Font2` atlas renderer with newline handling |
| `0x148` | `draw_text_small_fmt` | `void draw_text_small_fmt(float x, float y, const char *fmt, ...)` | high | formatted small-font text (wrapper around `0x144`) |
| `0x14c` | `measure_text_width` | `int measure_text_width(char *text)` | confirmed | exact-matched maximum-line width metric for newline-delimited small-font text |

The working vtable skeleton lives in the Zig workspace under `crimson-zig/` once a
signature is confirmed. Until then, the authoritative source is the vtable map
JSON in `analysis/ghidra/derived/`.


## Next steps

1. Validate the high-callsite entries in the table above with runtime evidence.
2. Port confirmed signatures into the Zig workspace under `crimson-zig/`.
3. Validate behavior with runtime toggles (config, input, draw calls).
