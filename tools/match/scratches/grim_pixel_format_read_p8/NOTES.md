# `grim_pixel_format_read_p8`

Native target: `grim.dll` at `0x10019b6f` (100 bytes).

This P8 vtable reader walks one addressed row of byte indices, copies the
corresponding 16-byte RGBA float entry from the embedded 256-color palette, and
applies the active color key to the completed row.
