# `grim_pixel_format_init_dxt`

Native target: `grim.dll` at `0x1001ac4a` (498 bytes).

This is the shared DXT1-DXT5 base constructor. It recovers the descriptor's
horizontal and vertical block masks, codec callbacks and encoded block size,
4x4-aligned three-dimensional cache bounds, block counts, and empty cache
sentinels. The class layout is evidenced directly by the native field offsets.
