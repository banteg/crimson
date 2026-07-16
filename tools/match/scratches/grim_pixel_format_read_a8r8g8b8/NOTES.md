# `grim_pixel_format_read_a8r8g8b8`

Native target: `grim.dll` at `0x10019333` (166 bytes).

This A8R8G8B8 vtable reader expands packed BGRA bytes through `1/255` into
RGBA floats and applies the active color key to the completed row.
