# `grim_pixel_format_read_a8l8`

Native target: `grim.dll` at `0x10019c41` (137 bytes).

This A8L8 vtable reader expands each low luminance byte through `1/255` into
equal RGB floats and the high alpha byte into the fourth channel, then applies
the active color key to the completed row.
