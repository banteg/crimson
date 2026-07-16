# `grim_pixel_format_scalar_deleting_destroy_yuv`

Native target: `grim.dll` at `0x1001bc84` (28 bytes).

This is VC6's scalar deleting wrapper for the shared UYVY/YUY2 destructor. It
invokes the regular destructor and conditionally releases `this` from the
deleting flag.
