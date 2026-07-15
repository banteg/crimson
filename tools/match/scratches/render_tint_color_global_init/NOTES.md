# `render_tint_color_global_init`

Native target: `crimsonland.exe` at `0x0041e080` (41 bytes).

The CRT initializer seeds the shared UI/HUD tint RGBA value to
`(149/255, 175/255, 198/255, 0.7)`. All four stores are direct constant writes
to the runtime-backed color at `0x004965f8`.
