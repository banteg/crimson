# `grim_pixel_format_read_r5g6b5`

Native target: `grim.dll` at `0x10019475` (165 bytes).

This reader expands packed R5G6B5 words through the native `1/31` and `1/63`
scales, emits one for alpha, and applies the active color key.
