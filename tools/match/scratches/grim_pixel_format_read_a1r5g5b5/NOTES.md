# `grim_pixel_format_read_a1r5g5b5`

Native target: `grim.dll` at `0x100195bc` (176 bytes).

This reader expands packed A1R5G5B5 colors through `1/31`, converts the high
alpha bit directly to zero or one, and applies the active color key.
