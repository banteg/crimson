# `grim_pixel_format_read_a8p8`

Native target: `grim.dll` at `0x10019ae8` (135 bytes).

This A8P8 vtable reader copies the embedded palette's 16-byte RGBA entry for
each low-byte index, replaces alpha from the high byte through `1/255`, and
applies the active color key to the completed row.
