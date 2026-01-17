# Grim2D overview

Grim2D is the game's 2D rendering + input facade exposed by `grim.dll`.
`crimsonland.exe` calls `GRIM__GetInterface` to obtain a vtable-backed object
and then drives all rendering, text, textures, and input queries through the
vtable.

At a high level, Grim2D provides:

- 2D rendering on a Direct3D8 device: textured quads, lines, circles, and UI
  primitives with batching and per-vertex color/UV state.
- Bitmap text rendering for mono and small fonts, with width tables and
  formatted wrappers.
- Texture lifecycle helpers (create, load, validate, destroy) and render target
  switching for offscreen draws.
- Input/config/time helpers: keyboard/mouse/joystick queries, config floats,
  and timing values used by the game loop.

## Data map highlights (grim.dll)

High-confidence globals from the grim.dll decompilation:

- **Interface:** `grim_interface_vtable` (vtable base) and `grim_interface_instance` (singleton object).
- **D3D core:** `grim_d3d8`, `grim_d3d_device`, `grim_d3d8_probe` (temporary Create8 check).
- **Render targets:** `grim_backbuffer_surface` and `grim_render_target_surface`.
- **Texture slots:** `grim_texture_slots` (handle-indexed texture pointer table).
- **Config storage:** `grim_config_blob` plus `grim_config_var0_table`..`grim_config_var3_table`.
- **Font tables:** `grim_font2_char_map`, `grim_font2_glyph_widths`, `grim_font2_uv_u`,
  `grim_font2_uv_v`, and `grim_font2_texture_handle`.
