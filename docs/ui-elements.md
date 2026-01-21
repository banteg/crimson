---
tags:
  - status-draft
---

# UI elements

**Status:** Draft

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
(`0x0048f20c`), for a total of **41 pointers** (`0xA4` bytes).

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
| 0x2fc | time_since_ready | Increments up to `0x100` after `ready=1`. |
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
short "glow" re-draw (blend mode differs) while `time_since_ready < 0x100`,
using:

`alpha_glow = 0xFF - (time_since_ready / 2)`
