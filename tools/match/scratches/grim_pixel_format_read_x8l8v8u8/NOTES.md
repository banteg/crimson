# `grim_pixel_format_read_x8l8v8u8`

Native target: `grim.dll` at `0x10019e86` (145 bytes).

This X8L8V8U8 vtable reader expands the two signed vector bytes through
`1/128`, emits zero for the third channel, expands the unsigned luminance byte
through `1/255` into the fourth channel, and ignores the padding byte. It then
applies the active color key to the completed row.
