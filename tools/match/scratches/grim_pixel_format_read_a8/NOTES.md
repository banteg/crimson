# `grim_pixel_format_read_a8`

Native target: `grim.dll` at `0x10019925` (114 bytes).

This A8 vtable reader walks one addressed row of alpha bytes, emits zero for
all three RGB channels, expands alpha through the native `1/255` scale, and
applies the active color key to the completed row.
