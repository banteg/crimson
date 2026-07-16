# `grim_pixel_format_read_r16`

Native target: `grim.dll` at `0x1001a2bc` (140 bytes).

This 48-bit R16 vtable reader walks the stored row byte count, expands three
16-bit source channels through `1/65535` in BGR-to-RGB order, emits one for
alpha, and applies the active color key to the completed row.

The loop bound uses the base format's `row_size` field at `+0x1064`, whose
meaning is independently established by `grim_pixel_format_init` as
`bytes_per_pixel * width`.
