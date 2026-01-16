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
- `source/decompiled/grim2d_vtable_callsites.json` (full callsite index with line numbers)

The JSON includes offset, callsite count, unique functions, and sample lines.

We also dumped the Grim2D vtable itself from `game/grim.dll` and joined the
two datasets:

- `source/decompiled/grim2d_vtable_entries.json`
- `source/decompiled/grim2d_vtable_map.json`

The map JSON includes function size, calling convention, return type, parameter
count, and the raw Ghidra signature for faster triage.

We now filter vtable exports to entries that resolve into the `.text` section
(84 entries / 0x150 bytes). Values after `0x14c` in the raw table look like
data, not executable pointers.

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
- `0x60`/`0x70`/`0x74` read the DirectInput mouse deltas, while
  `0x64`/`0x68`/`0x6c` update or return the accumulated mouse position.

## Provisional mapping (in progress)

| Offset | Name | Signature (guess) | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `0x0` | `release` | `void release(void)` | medium | vtable destructor (operator_delete) |
| `0x4` | `set_paused` | `void set_paused(int paused)` | low | toggles update loop |
| `0x8` | `get_version` | `float get_version(void)` | low | returns constant 1.21 |
| `0xc` | `check_device` | `int check_device(void)` | low | device creation test |
| `0x10` | `apply_config` | `int apply_config(void)` | medium | invoked by "...invoking grim config" log |
| `0x14` | `init_system` | `int init_system(void)` | high | returns success before game starts |
| `0x18` | `shutdown` | `void shutdown(void)` | high | shutdown path before DLL release |
| `0x1c` | `apply_settings` | `void apply_settings(void)` | low | called after config copy |
| `0x20` | `set_render_state` | `void set_render_state(uint32_t state, uint32_t value)` | high | D3D-style render state usage |
| `0x24` | `get_config_var` | `void * get_config_var(...)` | low | returns pointer to config var (args vary) |
| `0x28` | `get_error_text` | `char * get_error_text(void)` | medium | error string for MessageBox |
| `0x2c` | `clear_color` | `void clear_color(float r, float g, float b, float a)` | medium | clear color before render |
| `0x30` | `set_render_target` | `int set_render_target(int target_index)` | low | `-1` resets to backbuffer |
| `0x34` | `get_time_ms` | `int get_time_ms(void)` | medium | frame time accumulator (ms) |
| `0x38` | `set_time_ms` | `void set_time_ms(int ms)` | medium | overrides time accumulator |
| `0x3c` | `get_frame_dt` | `float get_frame_dt(void)` | medium | clamped frame delta |
| `0x40` | `get_fps` | `float get_fps(void)` | medium | frame rate estimate |
| `0x44` | `is_key_down` | `bool is_key_down(uint32_t key)` | high | Ctrl/arrow keycodes |
| `0x48` | `was_key_pressed` | `bool was_key_pressed(uint32_t key)` | high | edge-triggered key checks |
| `0x4c` | `flush_input` | `void flush_input(void)` | low | clears buffered input/device state |
| `0x50` | `get_key_char` | `int get_key_char(void)` | high | console text input |
| `0x54` | `set_key_char_buffer` | `void set_key_char_buffer(uint8_t *buffer, int *count, int size)` | low | input char ring buffer |
| `0x58` | `is_mouse_button_down` | `bool is_mouse_button_down(int button)` | medium | button 0 used |
| `0x5c` | `was_mouse_button_pressed` | `bool was_mouse_button_pressed(int button)` | low | edge-triggered mouse button |
| `0x60` | `get_mouse_wheel_delta` | `float get_mouse_wheel_delta(void)` | high | +/- wheel to change selection |
| `0x64` | `set_mouse_pos` | `void set_mouse_pos(float x, float y)` | medium | updates mouse position |
| `0x68` | `get_mouse_x` | `float get_mouse_x(void)` | medium | mouse position X |
| `0x6c` | `get_mouse_y` | `float get_mouse_y(void)` | medium | mouse position Y |
| `0x70` | `get_mouse_dx` | `float get_mouse_dx(void)` | medium | mouse delta X |
| `0x74` | `get_mouse_dy` | `float get_mouse_dy(void)` | medium | mouse delta Y |
| `0x78` | `get_mouse_dx_indexed` | `float get_mouse_dx_indexed(int index)` | low | mouse delta X (indexed) |
| `0x7c` | `get_mouse_dy_indexed` | `float get_mouse_dy_indexed(int index)` | low | mouse delta Y (indexed) |
| `0x80` | `is_key_active` | `bool is_key_active(int key)` | medium | uses key mapping entries |
| `0x84` | `get_config_float` | `float get_config_float(int id)` | medium | IDs `0x13f..0x155` |
| `0x88` | `get_slot_float` | `float get_slot_float(int index)` | low | float slot accessor |
| `0x8c` | `get_slot_int` | `int get_slot_int(int index)` | low | int slot accessor |
| `0x90` | `set_slot_float` | `void set_slot_float(int index, float value)` | low | float slot setter |
| `0x94` | `set_slot_int` | `void set_slot_int(int index, int value)` | low | int slot setter |
| `0x98` | `get_joystick_x` | `int get_joystick_x(void)` | low | joystick axis X (raw) |
| `0x9c` | `get_joystick_y` | `int get_joystick_y(void)` | low | joystick axis Y (raw) |
| `0xa0` | `get_joystick_z` | `int get_joystick_z(void)` | low | joystick axis Z (raw) |
| `0xa4` | `get_joystick_pov` | `int get_joystick_pov(int index)` | low | joystick POV hat value |
| `0xa8` | `is_joystick_button_down` | `bool is_joystick_button_down(int button)` | low | joystick button state |
| `0xac` | `create_texture` | `bool create_texture(const char *name, int width, int height)` | medium | terrain texture path |
| `0xb0` | `recreate_texture` | `bool recreate_texture(int handle)` | low | recreate texture object (pool/format?) |
| `0xb4` | `load_texture` | `bool load_texture(const char *name, const char *path)` | high | `(name, filename)` |
| `0xb8` | `validate_texture` | `bool validate_texture(int handle)` | low | validates texture handle |
| `0xbc` | `destroy_texture` | `void destroy_texture(int handle)` | low | release texture handle |
| `0xc0` | `get_texture_handle` | `int get_texture_handle(const char *name)` | high | returns `-1` on missing |
| `0xc4` | `bind_texture` | `void bind_texture(int handle, int stage)` | medium | often `(handle, 0)` |
| `0xc8` | `draw_fullscreen_quad` | `void draw_fullscreen_quad(void)` | low | full-screen quad with current texture |
| `0xcc` | `draw_fullscreen_color` | `void draw_fullscreen_color(float r, float g, float b, float a)` | medium | fade/overlay quad (often black + alpha) |
| `0xd0` | `draw_rect_filled` | `void draw_rect_filled(float *xy, float w, float h)` | low | UI panel fill / background quad |
| `0xd4` | `draw_rect_outline` | `void draw_rect_outline(float *xy, float w, float h)` | low | UI panel outline/frame |
| `0xd8` | `draw_circle_filled` | `void draw_circle_filled(float x, float y, float radius)` | low | triangle fan circle fill |
| `0xdc` | `draw_circle_outline` | `void draw_circle_outline(float x, float y, float radius)` | low | triangle strip ring/outline |
| `0xe0` | `draw_line` | `void draw_line(float *p0, float *p1, float thickness)` | low | computes quad from endpoints |
| `0xe4` | `draw_line_quad` | `void draw_line_quad(float *p0, float *p1, float *half_vec)` | low | uses precomputed half-width vector |
| `0xec` | `flush_batch` | `void flush_batch(void)` | medium | flushes batch when buffer fills |
| `0xe8` | `begin_batch` | `void begin_batch(void)` | high | start buffered quad batch |
| `0xf0` | `end_batch` | `void end_batch(void)` | high | flush buffered batch |
| `0xf4` | `submit_vertex_raw` | `void submit_vertex_raw(const float *vertex)` | low | push 1 raw vertex (7 floats) |
| `0xf8` | `submit_quad_raw` | `void submit_quad_raw(const float *verts)` | low | push 4 raw vertices (28 floats) |
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
| `0x124` | `draw_quad_rotated_matrix` | `void draw_quad_rotated_matrix(float x, float y, float w, float h)` | low | quad using rotation matrix |
| `0x128` | `submit_vertices_transform` | `void submit_vertices_transform(float *verts, int count, float *offset, float *matrix)` | low | rotate + translate batch verts |
| `0x12c` | `submit_vertices_offset` | `void submit_vertices_offset(float *verts, int count, float *offset)` | low | translate batch verts |
| `0x130` | `submit_vertices_offset_color` | `void submit_vertices_offset_color(float *verts, int count, float *offset, float *color)` | low | translate + set color |
| `0x134` | `submit_vertices_transform_color` | `void submit_vertices_transform_color(float *verts, int count, float *offset, float *matrix, float *color)` | low | rotate + translate + color |
| `0x138` | `draw_quad_points` | `void draw_quad_points(float x0, float y0, float x1, float y1, float x2, float y2, float x3, float y3)` | low | quad from 4 points |
| `0x13c` | `draw_text_mono` | `void draw_text_mono(float x, float y, const char *text)` | medium | fixed 16px grid; handles a few extended codes |
| `0x140` | `draw_text_mono_fmt` | `void draw_text_mono_fmt(float x, float y, const char *fmt, ...)` | medium | printf-style wrapper |
| `0x144` | `draw_text_small` | `void draw_text_small(float x, float y, const char *text)` | medium | uses `smallFnt.dat` widths + `GRIM_Font2` |
| `0x148` | `draw_text_small_fmt` | `void draw_text_small_fmt(float x, float y, const char *fmt, ...)` | medium | formatted small-font text (wrapper around `0x144`) |
| `0x14c` | `measure_text_width` | `int measure_text_width(const char *text)` | medium | width metric for small font |

The working vtable skeleton lives in:

- `source/clean/grim_api.h`

## Next steps

1. Expand the provisional mapping table as evidence improves.
2. Refine signatures in `source/clean/grim_api.h`.
3. Validate behavior with runtime toggles (config, input, draw calls).
