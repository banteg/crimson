# `grim_pixel_format_read_a4l4`

Native target: `grim.dll` at `0x10019cca` (137 bytes).

This A4L4 vtable reader expands each low luminance nibble through `1/15` into
equal RGB floats and the high alpha nibble into the fourth channel, then
applies the active color key to the completed row.
