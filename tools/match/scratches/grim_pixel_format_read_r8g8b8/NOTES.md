# `grim_pixel_format_read_r8g8b8`

Native target: `grim.dll` at `0x100192a7` (140 bytes).

This 24-bit R8G8B8 vtable reader walks the stored row byte count, expands BGR
bytes through `1/255` into RGB order, emits one for alpha, and applies the
active color key to the completed row.
