---
tags:
  - status-analysis
---

# UI elements
This page documents the UI element struct used by `ui_element_render` and the
menu/button helpers. `ui_element_t` (0x318 bytes) is fully typed in
`third_party/headers/crimsonland_types.h` and used by the byte-matched
`decomp/1.9/crimsonland/ui_elements/ui_element_render.cpp` and
`ui_element_update.cpp`.

## Overview

`ui_element_render` takes a pointer to a large struct that stores:

- Active/enabled flags.
- Position and sizing.
- Vertex/UV/color blocks for one or more quads.
- Optional click callback.
- Optional numeric counter text.

UI elements are referenced via a fixed table of pointers from
`ui_element_table_end` (`0x0048f168`) through `ui_element_table_start`
(`0x0048f208`), for a total of **41 pointers** (`0xA4` bytes).

In `data_map.json` this table is now labeled as typed slot pointers:

- `ui_element_table_slot_01_main_menu_aux` (`0x0048f16c`)
- `ui_element_table_slot_02_main_menu_primary` (`0x0048f170`)
- `ui_element_table_slot_03_main_menu_play_game` (`0x0048f174`)
- `ui_element_table_slot_04_main_menu_options` (`0x0048f178`)
- `ui_element_table_slot_05_main_menu_statistics` (`0x0048f17c`)
- `ui_element_table_slot_06_main_menu_footer_a` (`0x0048f180`)
- `ui_element_table_slot_07_main_menu_footer_b` (`0x0048f184`)
- `ui_element_table_slot_08..ui_element_table_slot_39` for the remaining
  state-specific slots assigned in `ui_menu_layout_init`.

The pointee storage blocks are also typed/labeled as `ui_element_t` globals
(`ui_element_slot_*`), e.g.:

- `ui_element_slot_03_main_menu_play_game` (`0x004878c0`)
- `ui_element_slot_12_layout_a` (`0x004897b0`)
- `ui_element_slot_18_layout_b` (`0x0048d590`)
- `ui_element_slot_32_layout_c` (`0x00488e68`)
- `ui_element_slot_40` (`0x0048ee50`)

Additional adjacent globals now mapped:

- `ui_menu_layout_init_latch` (`0x0048f164`) is set to `1` at the end of
  `ui_menu_layout_init`.
- `ui_perk_prompt_element` (`0x0048f20c`) is the special perk prompt element
  rendered by `perk_prompt_update_and_render`.
- `ui_perk_prompt_on_activate` (`0x0048f240`) is the prompt element callback
  slot (seeded to `ui_callback_noop` during layout init).
- `ui_perk_prompt_levelup_element` (`0x0048f330`) is a nested UI block loaded
  from `ui\ui_textLevelUp.jaz` and shaped during layout init.
- `ui_cursor_anim_timer` / `ui_cursor_pulse_phase`
  (`0x004902e8` / `0x004902ec`) drive cursor glow pulse timing in
  `ui_cursor_render`.
- `ui_aim_enhancement_anim_timer` / `ui_aim_enhancement_pulse_phase`
  (`0x004902f0` / `0x004902f4`) track aim overlay pulse timing in
  `ui_render_aim_enhancement`.
- `quest_kill_progress_ratio` (`0x004902f8`) stores the computed
  `kills / (spawned + queued)` value fed into `ui_draw_progress_bar`.

Template-pool globals (seeded in `ui_menu_template_pool_init`) are also mapped:

- `ui_template_pool_block_00..02` + `_mode` sentinels (`0x0048f808..0x0048fabc`)
- `ui_sign_crimson_template` + `ui_sign_crimson_template_mode`
  (`0x0048fac0` / `0x0048fba4`)
- `ui_menu_item_subtemplate_block_01..06` + `_mode` sentinels
  (`0x0048fd78..0x004902e4`)

### `ui_menu_item` subtemplate carving (`0x0048fd78..`)

`ui_menu_item_subtemplate_block_01..06` are now typed as
`ui_menu_item_subtemplate_block_t`:

- `slot_00..slot_07` are `0x1c` stride records.
- `ui_element_set_rect` establishes the complete record as transformed
  `x`/`y`, `z`, `rhw`, packed `color`, and texture `u`/`v`. It initializes the
  first four slots as a one-pixel-inset quad, with `z = 0.5`, `rhw = 1.0`, and
  white color, then adds the supplied XY offset.
- `+0xe0` is `texture_handle` (`ui_menu_item_subtemplate_block_*_texture_handle`).
- `+0xe4` is `quad_mode` (`ui_menu_item_subtemplate_block_*_mode`).

Observed transforms in `ui_menu_assets_init`:

- `block_01` is seeded from the menu panel quad payload (`memcpy` `0xe8` bytes).
- A stride `0x1c` loop subtracts `84.0` from every `slot_i.x` in `block_01`.
- `slot_02.y`/`slot_03.y` in `block_01` are shifted by `-116.0`.
- `slot_04.y..slot_07.y` in `block_01` are shifted by `+124.0`.
- `block_02` is copied from `block_01`, then `slot_04.y..slot_07.y` are shifted by
  `-100.0`.

The per-frame loop (`ui_elements_update_and_render`) iterates the table in
reverse: it starts at `ui_element_table_start` and decrements down to
`ui_element_table_end`. This means "earlier" pointers render on top.

Runtime cross-check (`analysis/frida/gameplay_state_capture_summary.json`) saw
heavy writes to `0x004902f0/0x004902f4` and periodic writes to
`0x004902e8/0x004902ec`, matching the static cursor/aim animation update paths.

## Struct view (ui_element_t)

Offsets are relative to the UI element base pointer. The three 0xe8-byte
blocks at `0x3c`, `0x124` and `0x20c` (vertices, texture handle, trailing
dword) also alias `ui_menu_item_subtemplate_block_t layers[3]`.

| Offset | Field | Notes |
| --- | --- | --- |
| 0x00 | active | If zero, `ui_element_update` and `ui_element_render` return immediately. |
| 0x01 | enabled | Set (with the panel-click SFX) once `ui_elements_timeline >= timeline_end_ms`, cleared while below it. Gates Enter activation and the enabled overlay pass. |
| 0x02 | focus_disabled | `ui_element_update` skips the element when nonzero. |
| 0x04 | use_offset_render | `0` = transform (`pos` + rotation matrix), `1` = offset (`pos` + `render_offset`). |
| 0x08 | render_offset_x | Slide-in offset derived from the quad width during the transition; zero once fully in. |
| 0x0c | render_offset_y | Always zeroed by `ui_element_update`. |
| 0x10 | timeline_end_ms | Timeline value at which the element is fully in (default `300`). |
| 0x14 | timeline_start_ms | Timeline value at which the slide starts (default `0`). |
| 0x18 | pos_x | Base X used for quad placement and hover bounds. |
| 0x1c | pos_y | Base Y used for quad placement and hover bounds. |
| 0x20 | hover_min_x | Hover/click bounds (screen space), set by `ui_element_layout_calc`. |
| 0x24 | hover_min_y | Hover/click bounds (screen space). |
| 0x28 | hover_max_x | Hover/click bounds (screen space). |
| 0x2c | hover_max_y | Hover/click bounds (screen space). |
| 0x30 | label_id | Menu label index (default `57`; set per slot in `ui_menu_layout_init`). |
| 0x34 | on_activate | Callback on click/Enter. |
| 0x38 | on_update | Optional callback run at the end of `ui_element_render`. |
| 0x3c | vertices[8] | Main vertex block (`ui_element_vertex_t`, 0x1c bytes each). |
| 0x11c | texture_handle | Main texture handle (`-1` disables). |
| 0x120 | vertex_count | `4` for a single quad; `8` for a three-piece panel drawn as quads from vertices 0–3, 2–5 and 4–7. |
| 0x124 | overlay_vertices[8] | Overlay (label) quad. |
| 0x204 | overlay_texture_handle | Overlay texture handle (`-1` disables). |
| 0x20c | enabled_overlay_vertices[8] | Second overlay block; its alpha follows the ready glow. |
| 0x2ec | secondary_overlay_texture_handle | Initialized to `-1`. |
| 0x2f4 | hover_enter_played | Set while the mouse is inside the hover bounds. |
| 0x2f8 | hover_amount | Hover lerp value, clamped 0..1000. |
| 0x2fc | time_since_ready | Initialized to `0x100` in `ui_element_init_defaults` and increments in `ui_element_update`; clicks need `>= 255`. If it falls into `0..0xFF`, `ui_element_render` uses it to override glow alpha. |
| 0x300 | render_scale | When `0.0` and `cv_uiPointFilterPanels` is set, the element renders with point filtering. |
| 0x304 | rot_m00 | Rotation matrix (cos). |
| 0x308 | rot_m01 | Rotation matrix (-sin). |
| 0x30c | rot_m10 | Rotation matrix (sin). |
| 0x310 | rot_m11 | Rotation matrix (cos). |
| 0x314 | direction_flag | Slide-in direction; `ui_element_layout_calc` swaps vertex U pairs when set. |

## Related functions

- `ui_element_render` (`0x00446c40`) — focus + render path.
- `ui_focus_update` — focus navigation for the active element.
- `ui_focus_draw` — focus highlight rendering.
- `ui_button_update` — button helper that wraps element state and rendering.

## Key behaviors (decompiled)

### Bounds calculation (`ui_element_layout_calc`)

Buttons use an inset rectangle derived from the element's *local* quad and its
`pos_x/pos_y`:

- `w = vertices[2].x - vertices[0].x`
- `h = vertices[2].y - vertices[0].y`

Then:

- `hover_min_x = pos_x + vertices[0].x + w*0.54`
- `hover_min_y = pos_y + vertices[0].y + h*0.28`
- `hover_max_x = pos_x + vertices[2].x - w*0.05`
- `hover_max_y = pos_y + vertices[2].y - h*0.10`

### Hover amount

`hover_amount` is updated per frame:

- hovered: `+= dt_ms * 6`
- not hovered: `-= dt_ms * 2`
- clamp to `[0, 1000]`

### Overlay alpha

For clickable elements (`on_activate != NULL`), overlay alpha is:

`alpha = 100 + floor(hover_amount * 155 / 1000)`

For non-clickable elements it uses a constant alpha (`200`).

### Shadow and glow passes (`ui_element_render`)

When `config_blob.shadows_enabled` (`0x00480356`) is nonzero:

- A shadow copy of the main quad is drawn at `(pos_x+7, pos_y+7)` with tint
  `0x44444444`.

Additionally, after drawing the overlay normally, `ui_element_render` performs a
"glow" re-draw in an additive blend mode for clickable + enabled elements. If
`time_since_ready` is in `0..0xFF`, it overrides the glow alpha using:

`alpha_glow = 0xFF - (time_since_ready / 2)`
