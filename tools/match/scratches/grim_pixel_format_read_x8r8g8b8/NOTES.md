# `grim_pixel_format_read_x8r8g8b8`

Native target: `grim.dll` at `0x100193d9` (156 bytes).

This X8R8G8B8 vtable reader expands packed BGR bytes through `1/255`, ignores
the high padding byte, emits one for alpha, and applies the active color key.
