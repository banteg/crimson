# `grim_pixel_format_read_v8u8`

Native target: `grim.dll` at `0x10019d53` (130 bytes).

This V8U8 vtable reader expands each signed byte pair through `1/128` into the
first two vector channels, emits zero and one for the remaining channels, and
applies the active color key to the completed row.
