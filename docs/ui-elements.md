---
tags:
  - status-analysis
---

# UI elements
This page documents the UI element struct used by `ui_element_render` and the
menu/button helpers. The layout is inferred from the decompile and is still
partial.

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
- Per-slot `x`/`y` are high confidence from copy/offset loops in
  `ui_menu_assets_init`.
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

## Struct view (ui_element_t)

This is a *working* layout for the fields we actively rely on. Many unknown
fields remain.

## Known fields (partial)

Offsets below are relative to the UI element base pointer.

| Offset | Field | Notes |
| --- | --- | --- |
| 0x00 | active | If zero, `ui_element_render` returns immediately. |
| 0x01 | ready | Becomes 1 when `ui_elements_timeline >= start_time_ms`. |
| 0x02 | disabled | Skips hover/click logic when nonzero. |
| 0x04 | render_mode | `0 = transform (pos+matrix)`, `1 = offset (pos+slide)` |
| 0x08 | slide_x | Computed during transitions; used when `render_mode == 1`. |
| 0x0c | slide_y | Unused in most menus; reserved. |
| 0x10 | start_time_ms | Transition "fully visible" time used by timeline logic. |
| 0x14 | end_time_ms | Transition "fully hidden" time (start of lerp interval). |
| 0x18 | pos_x | Base X used for quad placement and highlight math. |
| 0x1c | pos_y | Base Y used for quad placement and highlight math. |
| 0x20 | bounds_left | Click/hover bounds (screen space). |
| 0x24 | bounds_top | Click/hover bounds (screen space). |
| 0x28 | bounds_right | Click/hover bounds (screen space). |
| 0x2c | bounds_bottom | Click/hover bounds (screen space). |
| 0x34 | on_activate | Function pointer called on click/confirm. |
| 0x38 | custom_render | Optional extra draw callback after main passes. |
| 0x3c | quad0 | Main quad vertex block (4 verts). |
| 0x74 | quad1 | Stretch/panel quad #2 (only when `quad_mode == 8`). |
| 0xac | quad2 | Stretch/panel quad #3 (only when `quad_mode == 8`). |
| 0x11c | texture_handle | Main texture handle (`-1` disables). |
| 0x120 | quad_mode | `4` for normal quads, `8` for 3-piece panels. |
| 0x124 | overlay_quad | Overlay quad (menu item text). |
| 0x204 | overlay_texture_handle | Overlay texture handle (`-1` disables). |
| 0x2f4 | hover_enter_played | Gate for "hover enter" SFX. |
| 0x2f8 | hover_amount | Hover lerp value, clamped 0..1000. |
| 0x2fc | time_since_ready | Initialized to `0x100` in `ui_element_init_defaults` and increments in `ui_element_update`. If it ever falls into `0..0xFF`, `ui_element_render` uses it to override glow alpha. |
| 0x300 | render_scale | Used to pick a special render state when zero. |
| 0x304 | rot_m00 | Rotation matrix (cos). |
| 0x308 | rot_m01 | Rotation matrix (-sin). |
| 0x30c | rot_m10 | Rotation matrix (sin). |
| 0x310 | rot_m11 | Rotation matrix (cos). |
| 0x314 | direction_flag | Affects offscreen direction + UV swapping (see below). |

## Related functions

- `ui_element_render` (`FUN_00446c40`) — focus + render path.
- `ui_focus_update` — focus navigation for the active element.
- `ui_focus_draw` — focus highlight rendering.
- `ui_button_update` — button helper that wraps element state and rendering.

## Key behaviors (decompiled)

### Bounds calculation (`FUN_0044fb50`)

Buttons use an inset rectangle derived from the element's *local* quad and its
`pos_x/pos_y`:

- `w = quad0.v2.x - quad0.v0.x`
- `h = quad0.v2.y - quad0.v0.y`

Then:

- `left   = pos_x + quad0.v0.x + w*0.54`
- `top    = pos_y + quad0.v0.y + h*0.28`
- `right  = pos_x + quad0.v2.x - w*0.05`
- `bottom = pos_y + quad0.v2.y - h*0.10`

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

When `config_blob.reserved0[0x0e]` (aka `fx_detail_0`) is nonzero:

- A shadow copy of the main quad is drawn at `(pos_x+7, pos_y+7)` with tint
  `0x44444444`.

Additionally, after drawing the overlay normally, `ui_element_render` performs a
"glow" re-draw in an additive blend mode for clickable + enabled elements. If
`time_since_ready` is in `0..0xFF`, it overrides the glow alpha using:

`alpha_glow = 0xFF - (time_since_ready / 2)`
