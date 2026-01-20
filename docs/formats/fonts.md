---
tags:
  - status-draft
---

# Fonts

**Status:** Draft

Crimsonland ships two bitmap fonts:

- **Small font** (`smallFnt.dat` + `smallWhite.png`): variable-width, 16x16 atlas, used by `grim_draw_text_small`. [static]
- **Grim2D mono font** (resource id `0x6f`): fixed 16px grid, used by `grim_draw_text_mono`. [static]

## Small font (smallFnt.dat)

### Location

- `game_bins/crimsonland/1.9.93-gog/crimson.paq`: `load\smallFnt.dat`, `load\smallWhite.tga`
- Extracted to `artifacts/assets/crimson/load/smallFnt.dat` and `artifacts/assets/crimson/load/smallWhite.png`

### Layout

```
u8 widths[256]
```

`widths[i]` is the glyph advance in pixels for glyph index `i` (0-255).
The renderer uses the same value to size the UV width.

### Atlas + UVs

The extracted `smallWhite.png` (from `smallWhite.tga`) is 256x256 RGBA. The renderer treats it as a 16x16 grid,
so each glyph cell is 16x16. UV origins are:

```
u0 = (idx % 16) / 16
v0 = (idx / 16) / 16
u1 = u0 + widths[idx] / 256
v1 = v0 + 1/16
```

A small bias of 1/512 is applied to the U/V values in code to reduce bleeding.

### Rendering hooks (grim.dll)

- `FUN_10005eb0` loads `load\smallFnt.dat` and copies 0x100 bytes into `grim_font2_glyph_widths`.
- `grim_measure_text_width` (vtable offset `0x14c`) sums widths and returns the widest line.
- `grim_draw_text_small` (vtable offset `0x144`) binds `GRIM_Font2` and emits quads using the UV math above.
- `grim_font2_char_map` is initialized as an identity lookup table, so glyph index
  equals the byte value. [static]

## Grim2D mono font (grim_draw_text_mono)

### Source

- `grim_draw_text_mono` binds `grim_font_texture`, which is loaded from Grim2D resources
  (resource id `0x6f`). [static]
- This is not yet confirmed to match `default_font_courier.tga` from `crimson.paq`. [static]

### Behavior

- **Advance**: `16 * scale` (fixed). [static]
- **Line height**: `28 * scale` (newline step). [static]
- **Draw size**: `32 * scale` width x `32 * scale` height. [static]
- **Visual effect**: Characters are drawn at 2x the size of their horizontal spacing, creating a dense, tall appearance (effective 1:2 aspect ratio relative to the grid). [static]
- **UVs**: 16x16 table (`grim_font2_uv_u/v`), indexed directly by byte value (`grim_font2_char_map` is identity). [static]
- **Special codes**: Handles 0xA7, 0xE4, 0xE5, 0xF6 and `\n`. [static]

### Quest title overlay (runtime evidence)

The quest HUD renders the level number and title with separate mono draws:

- **Title** (`"Land Hostile"`) uses the base scale (0.75 at 640px width, 0.8 at larger widths). [static+runtime]
- **Number** (`"1.1"`) uses `base_scale - 0.2` (observed 0.55 when base is 0.75). [runtime]
- **Opacity**: number alpha is **50%** of title alpha (ratio 0.5 across captures). [runtime]
- **Position**: number is offset left of the title; at base scale 0.75 the number draw origin is ~34.8 px left of the title origin, with a ~4.05 px lower Y. [runtime]

Evidence: `artifacts/frida/share/quest_title_colors.jsonl` (quest HUD capture on 2026-01-20). Runtime logs show paired `draw_text_mono` calls for the title and number with the scale/alpha ratios above.

## Sample render (interactive)

```
uv run crimson view fonts
```
