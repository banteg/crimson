# `grim_pixel_format_write_yuv_cache`

Native target: `grim.dll` at `0x1001ab16` (141 bytes).

This YUV vtable write method converts incoming RGBA floats into the format's
working coordinate space when required, loads the packed-YUV cache window for
the requested row and depth, copies one logical row into the aligned cache, and
marks that cache dirty for the later packed-YUV flush.
