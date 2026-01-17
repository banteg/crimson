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

## Known fields (partial)

Offsets below are relative to the UI element base pointer.

| Offset | Field | Notes |
| --- | --- | --- |
| 0x00 | active | If zero, `ui_element_render` returns immediately. |
| 0x01 | enabled | Must be nonzero for click/activate handling. |
| 0x18 | pos_x | Base X used for quad placement and highlight math. |
| 0x1c | pos_y | Base Y used for quad placement and highlight math. |
| 0x34 | on_activate | Function pointer called on click/confirm. |
| 0x3c | quad_0 | Vertex/UV/color block passed into `grim_submit_vertices_transform_color`. |
| 0x74 | quad_1 | Secondary quad block, used when `0x120 == 8`. |
| 0xac | quad_2 | Third quad block, used when `0x120 == 8`. |
| 0x11c | texture_handle | Passed into `grim_bind_texture` when not `-1`. |
| 0x120 | quad_mode | When `== 8`, draws extra quads at `0x74` and `0xac`. |
| 0x204 | counter_id | When not `-1`, updates digit fields for a counter display. |
| 0x2f8 | counter_value | Value rendered into the digit slots. |
| 0x2fc | counter_timer | Increments up to `0x100` while focused. |
| 0x300 | render_scale | Used to pick a special render state when zero. |
| 0x304 | rot_m00 | Cos/sin matrix for rotating quads. |
| 0x308 | rot_m01 | Cos/sin matrix for rotating quads. |
| 0x30c | rot_m10 | Cos/sin matrix for rotating quads. |
| 0x310 | rot_m11 | Cos/sin matrix for rotating quads. |

## Related functions

- `ui_element_render` (`FUN_00446c40`) — focus + render path.
- `ui_focus_update` — focus navigation for the active element.
- `ui_focus_draw` — focus highlight rendering.
- `ui_button_update` — button helper that wraps element state and rendering.
