---
tags:
  - status-draft
---

# Small font (smallFnt.dat)

**Status:** Draft

The small font is stored as a 256-byte width table and a 16x16 glyph atlas.

## Location

- `game_bins/crimsonland/1.9.93-gog/crimson.paq`: `load\smallFnt.dat`, `load\smallWhite.tga`
- Extracted to `artifacts/assets/crimson/load/smallFnt.dat` and `artifacts/assets/crimson/load/smallWhite.png`


## smallFnt.dat layout

```
u8 widths[256]
```

`widths[i]` is the glyph advance in pixels for glyph index `i` (0-255).
The renderer uses the same value to size the UV width.

## Atlas + UVs

The extracted `smallWhite.png` (from `smallWhite.tga`) is 256x256 RGBA. The renderer treats it as a 16x16 grid,
so each glyph cell is 16x16. UV origins are:

```
u0 = (idx % 16) / 16
v0 = (idx / 16) / 16
u1 = u0 + widths[idx] / 256
v1 = v0 + 1/16
```

A small bias of 1/512 is applied to the U/V values in code to reduce bleeding.

## Rendering hooks (grim.dll)

- `FUN_10005eb0` loads `load\smallFnt.dat` and copies 0x100 bytes into `DAT_1005bad8`.
- `FUN_100096c0` (vtable offset `0x14c`) measures text width by summing widths;
  newline (0x0A) resets the line, and the max line width is returned.
- `FUN_10009730` (vtable offset `0x144`) draws the small font by binding
  texture `GRIM_Font2` and emitting quads with the UV math above.
- `DAT_1005a570` is initialized as an identity lookup table, so glyph index
  equals the byte value.


## Notes

- No kerning table is referenced; widths are the only per-glyph metric.
- Empty atlas cells observed at indices 32, 160, 253-255 (space + unused).
- The fixed-width mono font used by vtable offset `0x13c` (`grim_draw_text_mono`)
  binds `grim_font_texture`, which is loaded from Grim2D resources (resource id `0x6f`).
  This is not yet confirmed to match `default_font_courier.tga` from `crimson.paq`. [static]

## Mono font behavior (grim_draw_text_mono)

- Uses a fixed 16px grid: advance = `16 * scale`, line height = `16 * scale`. [static]
- UVs come from a 16x16 table (`grim_font2_uv_u/v`), indexed directly by byte value
  (`grim_font2_char_map` is identity). [static]
- Handles special codes 0xA7, 0xE4, 0xE5, 0xF6 in addition to newline. [static]


## Sample render

```
uv run paq font --assets-dir artifacts/assets --out artifacts/fonts/small_font_sample.png
```

Custom text:

```
uv run paq font --assets-dir artifacts/assets --text "Hello, world!" --scale 2.0
```
