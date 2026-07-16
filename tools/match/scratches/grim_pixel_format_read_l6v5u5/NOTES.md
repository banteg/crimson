# `grim_pixel_format_read_l6v5u5`

Native target: `grim.dll` at `0x10019dd5` (177 bytes).

This L6V5U5 vtable reader sign-extends the packed U/V five-bit components,
normalizes them through `1/16`, emits zero for the third channel, expands the
unsigned six-bit luminance through `1/63`, and applies the active color key to
the completed row.
