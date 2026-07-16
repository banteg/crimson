# `grim_pixel_format_read_yuv_cache`

Native target: `grim.dll` at `0x1001abbf` (111 bytes).

This YUV vtable read method loads the packed-YUV cache window for the requested
row and depth, copies one logical row of RGBA floats from its aligned cache
offset, and applies the active color key to the returned pixels.
