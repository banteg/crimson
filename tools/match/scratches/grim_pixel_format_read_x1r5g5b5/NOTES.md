# `grim_pixel_format_read_x1r5g5b5`

Native target: `grim.dll` at `0x1001951a` (162 bytes).

This reader expands the three five-bit X1R5G5B5 color channels through `1/31`,
ignores the high padding bit, emits one for alpha, and applies the color key.
