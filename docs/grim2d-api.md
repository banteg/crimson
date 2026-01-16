# Grim2D API vtable (draft)

This is a first-pass extraction of the Grim2D API vtable usage from the
classic `crimsonland.exe` decompilation. The engine interface pointer is
`DAT_0048083c` in `source/decompiled/crimsonland.exe_decompiled.c`.

The interface is created in `GRIM__GetInterface` (`grim.dll`), which sets the
object vtable to `PTR_LAB_1004c238` (address `0x1004c238` in the DLL).

We created functions at vtable entry addresses via
`scripts/ghidra_scripts/CreateGrim2DVtableFunctions.java` and re-exported
`grim.dll_functions.json` to capture those entry names. The latest vtable JSON
exports now include 84 entry points created from the vtable.

## Extraction artifact

We extracted all `(*DAT_0048083c + offset)` callsites and wrote them to:

- `source/decompiled/grim2d_vtable_calls.json`

The JSON includes offset, callsite count, unique functions, and sample lines.

We also dumped the Grim2D vtable itself from `game/grim.dll` and joined the
two datasets:

- `source/decompiled/grim2d_vtable_entries.json`
- `source/decompiled/grim2d_vtable_map.json`

The map JSON includes function size, calling convention, return type, parameter
count, and the raw Ghidra signature for faster triage.

We also generate an evidence appendix with callsite snippets:

- `docs/grim2d-api-evidence.md`

## Top offsets by callsite count

These are the most frequently used offsets (likely the core draw/state calls):

- `0x20` (206)
- `0x114` (203)
- `0x11c` (100)
- `0xf0` (86)
- `0x148` (86)
- `0xe8` (79)
- `0xc4` (66)
- `0xfc` (65)
- `0x100` (59)
- `0x48` (39)

## Input-ish offsets (evidence)

These offsets appear with keycodes or input-related values:

- `0x44` / `0x48` used with keycodes like `0x1d`, `0x9d`, `0xd0`, `200`
  in `FUN_00401a40` (likely key down / key pressed checks).
- `0x50` is a zero-arg call in `FUN_00401060` (likely a per-frame poll).
- `0x58` / `0x80` appear in input handling loops in `FUN_00446030`.
- `0x84` returns a float and is queried with IDs `0x13f..0x155`
  in `FUN_00448b50` (likely config values).

## Provisional mapping (in progress)

| Offset | Name | Signature (guess) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `0x10` | `apply_config` | `int apply_config(void)` | medium | invoked by "...invoking grim config" log |
| `0x14` | `init_system` | `int init_system(void)` | high | returns success before game starts |
| `0x18` | `shutdown` | `void shutdown(void)` | high | shutdown path before DLL release |
| `0x1c` | `apply_settings` | `void apply_settings(void)` | low | called after config copy |
| `0x24` | `get_config_var` | `void * get_config_var(...)` | low | returns pointer to config var (args vary) |
| `0x28` | `get_error_text` | `char * get_error_text(void)` | medium | error string for MessageBox |
| `0x2c` | `clear_color` | `void clear_color(float r, float g, float b, float a)` | medium | clear color before render |
| `0x30` | `set_render_target` | `int set_render_target(int target_index)` | low | `-1` resets to backbuffer |
| `0x20` | `set_render_state` | `void set_render_state(uint32_t state, uint32_t value)` | high | D3D-style render state usage |
| `0x44` | `is_key_down` | `bool is_key_down(uint32_t key)` | high | Ctrl/arrow keycodes |
| `0x48` | `was_key_pressed` | `bool was_key_pressed(uint32_t key)` | high | edge-triggered key checks |
| `0x50` | `get_key_char` | `int get_key_char(void)` | high | console text input |
| `0x58` | `is_mouse_button_down` | `bool is_mouse_button_down(int button)` | medium | button 0 used |
| `0x60` | `get_mouse_wheel_delta` | `float get_mouse_wheel_delta(void)` | high | +/- wheel to change selection |
| `0x80` | `is_key_active` | `bool is_key_active(int key)` | medium | uses key mapping entries |
| `0x84` | `get_config_float` | `float get_config_float(int id)` | medium | IDs `0x13f..0x155` |
| `0xac` | `create_texture` | `bool create_texture(const char *name, int width, int height)` | medium | terrain texture path |
| `0xb4` | `load_texture` | `bool load_texture(const char *name, const char *path)` | high | `(name, filename)` |
| `0xc0` | `get_texture_handle` | `int get_texture_handle(const char *name)` | high | returns `-1` on missing |
| `0xc4` | `bind_texture` | `void bind_texture(int handle, int stage)` | medium | often `(handle, 0)` |
| `0xcc` | `draw_fullscreen_color` | `void draw_fullscreen_color(float r, float g, float b, float a)` | medium | fade/overlay quad (often black + alpha) |
| `0xe8` | `begin_batch` | `void begin_batch(void)` | high | start buffered quad batch |
| `0xf0` | `end_batch` | `void end_batch(void)` | high | flush buffered batch |
| `0xfc` | `set_rotation` | `void set_rotation(float radians)` | medium | rotation before draw |
| `0x100` | `set_uv` | `void set_uv(float u0, float v0, float u1, float v1)` | high | UV coords |
| `0x104` | `set_atlas_frame` | `void set_atlas_frame(int atlas, int frame)` | high | atlas index + frame |
| `0x108` | `set_sub_rect` | `void set_sub_rect(int x, int y, int w, int h)` | medium | pixel rect/clip |
| `0x10c` | `set_uv_point` | `void set_uv_point(int index, float u, float v)` | medium | sets a single UV pair |
| `0x110` | `set_pivot` | `void set_pivot(const float *xy)` | low | pointer to float pair |
| `0x114` | `set_color` | `void set_color(float r, float g, float b, float a)` | high | RGBA floats |
| `0x118` | `set_color_slot` | `void set_color_slot(int index, float r, float g, float b, float a)` | low | updates a color slot/palette |
| `0x11c` | `draw_quad` | `void draw_quad(float x, float y, float w, float h)` | high | core draw call |
| `0x120` | `draw_quad_xy` | `void draw_quad_xy(float *xy, float w, float h)` | medium | quad using pointer to XY |
| `0x13c` | `draw_text_mono` | `void draw_text_mono(float x, float y, const char *text)` | medium | fixed 16px grid; handles a few extended codes |
| `0x140` | `draw_text_mono_fmt` | `void draw_text_mono_fmt(float x, float y, const char *fmt, ...)` | medium | printf-style wrapper |
| `0x144` | `draw_text_small` | `void draw_text_small(float x, float y, const char *text)` | medium | uses `smallFnt.dat` widths + `GRIM_Font2` |
| `0x148` | `draw_text_box` | `void draw_text_box(float x, float y, const char *text, ...)` | low | wrapping/layout variant |
| `0x14c` | `measure_text_width` | `int measure_text_width(const char *text)` | medium | width metric for small font |

The working vtable skeleton lives in:

- `source/clean/grim_api.h`

## Next steps

1. Expand the provisional mapping table as evidence improves.
2. Refine signatures in `source/clean/grim_api.h`.
3. Validate behavior with runtime toggles (config, input, draw calls).
