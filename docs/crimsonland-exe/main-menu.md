---
tags:
  - status-draft
---

# Main menu (state 0)

**Status:** Draft

This page documents the classic Crimsonland.exe **main menu** (game state `0`)
from decompiled code (Ghidra + Binary Ninja cross-checks). The goal is a
faithful reimplementation: same layout math, timings, and render passes.

## Frame pipeline (state 0)

In the main frame renderer, state `0` follows the "menu/world" render path:

1. Terrain background render.
2. Optional fullscreen fade overlay (`screen_fade_alpha`).
3. UI element timeline update + draw (`ui_elements_update_and_render`).
4. Perk prompt (usually inactive in menu).
5. Cursor draw.

## Keyboard navigation (state 0)

Main-menu focus navigation is **Tab-based** (not arrow keys):

- `Tab` cycles focus forward; `Shift+Tab` cycles focus backward (`ui_focus_update @ 0x0043d830`).
- `Enter` activates the focused element (`ui_element_render @ 0x00446c40`), but only once the element is enabled (fully visible).

## UI element table and ordering

UI elements live in a fixed pointer table:

- Range: `0x0048f168 .. 0x0048f20b` (`0xA4` bytes)
- Count: **41 pointers**

`ui_elements_update_and_render` iterates **backwards**:

- starts at `ui_element_table_start`
- decrements down to `ui_element_table_end`

So earlier pointers in the table draw **last** (on top).

## Assets and template rects (`ui_menu_assets_init @ 0x00419dd0`)

Menu UI templates are loaded once and then copied into per-screen elements.

### `ui_signCrimson.jaz` (logo sign)

`ui_element_set_rect(width, height, offsetX, offsetY)`:

- `width = 573.44`
- `height = 143.36`
- `offset = (-577.44, -62.0)`

The quad lives mostly in **negative X**, so placing the element at
`pos_x = screen_width + 4` anchors it to the right.

### `ui_menuItem.jaz` (menu item button)

- `width = 512.0`
- `height = 64.0`
- `offset = (-72.0, -60.0)`

The pivot is intentionally offset so the element can rotate in from the left.

### `ui_menuPanel.jaz` (panel)

This is **not used in state 0** (but used by other menus/screens):

- `width = 512.0`
- `height = 256.0`
- `offset = (20.0, -82.0)`

### Label overlay rect (inside `ui_menuItem`)

Each menu item has an overlay quad (later given UVs into `ui_itemTexts`):

- `width = 124.0`
- `height = 30.0`
- `offset = (270.0, -38.0)`

## Main menu composition (state 0)

`game_state_set(0)` activates:

- the logo sign
- menu item buttons (some conditional)
- no panel

The relevant table indices are:

| Table idx | Element | Role |
| ---: | --- | --- |
| 0 | `DAT_00487290` | Logo sign (`ui_signCrimson`) |
| 1 | `DAT_004875a8` | Unused/mystery (participates in layout adjustments) |
| 2 | `DAT_00488208` | Top item: `BUY NOW` (demo) or `MODS` (full). **Rewrite note:** `BUY NOW` is out of scope. |
| 3 | `DAT_004878c0` | `PLAY GAME` |
| 4 | `DAT_00487bd8` | `OPTIONS` |
| 5 | `DAT_00487ef0` | `STATISTICS` |
| 6 | `DAT_00488520` / `DAT_00488838` | `OTHER GAMES` or `QUIT` depending on config var 100 |
| 7 | `DAT_00488838` / `DAT_00488520` | `QUIT` or inactive placeholder |

Notes:

- `mods_any_available()` gates the `MODS` button in full version builds.
- A string config entry `grim_get_config_var(100)` controls whether the
  `OTHER GAMES` slot is present, and swaps table indices `6` and `7`.

## Base positions and timings (`ui_menu_layout_init @ 0x0044fcb0`)

### Logo position

- `pos_x = screen_width + 4`
- `pos_y = 70` (or `60` when `screen_width < 641`)

### Menu item positions (before adjustments)

All menu items start at `pos_x = -60` and:

- slot 0: `y = 210`
- slot 1: `y = 270`
- slot 2: `y = 330`
- slot 3: `y = 390`
- slot 4: `y = 450`
- slot 5: `y = 510` (only when `OTHER GAMES` is present; otherwise `QUIT` is at 450)

### Stagger timing + diagonal X shift (table idx 1..7)

All elements default to:

- `start_time_ms = 300`
- `end_time_ms = 0`

Then the layout loop adds `+100, +200, ... +700` ms to both `start_time_ms` and
`end_time_ms` (for table indices `1..7`). This keeps the interval length at
**300ms** while staggering each item by **100ms**.

In the same loop, it applies a diagonal X offset to later entries:

| Table idx | Slot | Base X | Extra shift | Final X |
| ---: | ---: | ---: | ---: | ---: |
| 2 | 0 | -60 | 0 | -60 |
| 3 | 1 | -60 | -20 | -80 |
| 4 | 2 | -60 | -40 | -100 |
| 5 | 3 | -60 | -60 | -120 |
| 6 | 4 | -60 | -80 | -140 |
| 7 | 5 | -60 | -100 | -160 |

## Resolution-dependent adjustments

### Widescreen vertical shift (applied after layout)

After layout, all UI elements except the logo (table idx `0`) receive:

`pos_y += (screen_width / 640.0) * 150.0 - 150.0`

Examples:

- `640` → `+0`
- `800` → `+37.5`
- `1024` → `+90`
- `1280` → `+150`

### Logo scaling (small and 800–1024 widths)

The logo quad is scaled in-place:

- when `screen_width < 641`: multiply vertex coords by `0.8` and add `+10` to
  several X coordinates.
- when `801 <= screen_width <= 1024`: multiply by `1.2` and also add `+10` to X.

### Small-width menu pack (screen_width < 641)

For table indices `1..7` the code:

- scales the main + overlay quads by `0.9`
- applies a per-element **local Y shift** to compress the vertical spacing

The per-element shift is `f = [-11, 0, 11, 22, 33, 44, 55]` (for indices `1..7`)
and each quad's local Y is adjusted by `y -= f`.

For menu slots (table idx `2..7`) this corresponds to local Y shifts:

- slot 0: `0`
- slot 1: `11`
- slot 2: `22`
- slot 3: `33`
- slot 4: `44`
- slot 5: `55`

## Label atlas (`ui_itemTexts.jaz`)

The menu labels are an 8-row atlas (row height = `1/8 = 0.125` in UV space):

| Row | Label |
| ---: | --- |
| 0 | BUY NOW *(out of scope for rewrite)* |
| 1 | PLAY GAME |
| 2 | OPTIONS |
| 3 | STATISTICS |
| 4 | MODS |
| 5 | OTHER GAMES |
| 6 | QUIT |
| 7 | BACK |

When entering state `0`, the game assigns overlay UVs for table indices `2..7`.
Important behavior:

- In full version, the top slot (idx `2`) forces row `4` (MODS), then the row
  sequence resets back to `0` for the next items.
- The normal row sequence skips `4` (so `3 -> 5`).
- If config var `100` is empty, table idx `6` is forced to row `6` (QUIT). The
  remaining row `7` is assigned to an element that is **inactive** in state `0`
  and therefore not visible.

## Animation (`ui_element_update @ 0x00446900`)

Menu items use `render_mode == 0` ("transform") and animate via rotation:

- Fully hidden: `angle = ±pi/2`
- Fully visible: `angle = 0`
- During transition: linearly lerp angle from `pi/2` to `0` over
  `[end_time_ms, start_time_ms]`

Rotation matrix:

```
m00 = cos(angle)
m01 = -sin(angle)
m10 = sin(angle)
m11 = cos(angle)
```

`slide_x` is computed for all elements, but is only used when
`render_mode == 1` ("offset"). For main menu items (`render_mode == 0`) it is
ignored by the render path.

## Hit testing bounds (`FUN_0044fb50 @ 0x0044fb50`)

Bounds are derived from quad0 v0/v2 and `pos_x/pos_y`:

- `w = v2.x - v0.x`
- `h = v2.y - v0.y`

Then:

- `left   = pos_x + v0.x + w*0.54`
- `top    = pos_y + v0.y + h*0.28`
- `right  = pos_x + v2.x - w*0.05`
- `bottom = pos_y + v2.y - h*0.10`

## Per-element render passes (`ui_element_render @ 0x00446c40`)

The element renderer draws, in order:

1. Optional **shadow** pass (when `fx_detail_0 != 0`):
   - draw at `(pos_x + 7, pos_y + 7)` with tint `0x44444444`
2. Main quad(s)
3. Overlay label quad
4. "Glow" overlay re-draw in additive blend (clickable + enabled elements):
   - always draws the overlay a second time with a different render state / blend mode
   - if `counter_timer` is in `0..0xFF`, it overrides the glow alpha:
     - `alpha_glow = 0xFF - counter_timer/2`

Note: `counter_timer` is initialized to `0x100` in `FUN_0044faa0` and (as far as we
can tell) only increments in `ui_element_update`, so this short alpha override
may never trigger for main-menu items unless something else resets the timer.

Overlay alpha for clickable elements:

`alpha = 100 + floor(hover_amount * 155 / 1000)`

Hover amount is updated per frame:

- hovered: `+= dt_ms * 6`
- not hovered: `-= dt_ms * 2`
- clamp to `[0, 1000]`
