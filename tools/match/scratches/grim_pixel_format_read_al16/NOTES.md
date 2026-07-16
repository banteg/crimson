# `grim_pixel_format_read_al16`

Native target: `grim.dll` at `0x1001a22e` (142 bytes).

This AL16 vtable reader expands the low 16-bit luminance channel through
`1/65535` into RGB, expands the high 16-bit alpha channel through the same
scale, and applies the active color key to the completed row.

MSVC 7.0 reproduces the native unsigned low-word conversion, including its
signed-`fild` plus `2^32` correction path.
