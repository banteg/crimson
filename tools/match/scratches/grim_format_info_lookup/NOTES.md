# `grim_format_info_lookup`

Native target: `grim.dll` at `0x1000aaa6` (36 bytes).

The helper linearly scans 36-byte D3D format descriptors from the table start
to the live end pointer and returns the dedicated default descriptor on miss.
