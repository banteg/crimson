# `grim_pixel_format_scalar_deleting_destroy_yuv_base`

Native target: `grim.dll` at `0x1001bc68` (28 bytes).

This VC6 scalar deleting wrapper occupies the shared YUV base vtable. It calls
the regular cache-owning YUV destructor directly; the UYVY/YUY2 wrapper uses the
nearby linker-emitted tail thunk instead.
