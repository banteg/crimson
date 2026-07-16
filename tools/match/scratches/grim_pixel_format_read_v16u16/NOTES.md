# `grim_pixel_format_read_v16u16`

Native target: `grim.dll` at `0x10019fae` (131 bytes).

This V16U16 vtable reader expands each signed 16-bit pair through `1/32768`
into the first two vector channels, emits zero and one for the remaining
channels, and applies the active color key to the completed row.
