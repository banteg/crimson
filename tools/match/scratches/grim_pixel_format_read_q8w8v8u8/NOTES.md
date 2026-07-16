# `grim_pixel_format_read_q8w8v8u8`

Native target: `grim.dll` at `0x10019f17` (151 bytes).

This Q8W8V8U8 vtable reader expands all four signed bytes through `1/128`
into a four-component float vector and applies the active color key to the
completed row.
