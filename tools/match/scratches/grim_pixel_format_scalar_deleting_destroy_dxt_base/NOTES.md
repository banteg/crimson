# `grim_pixel_format_scalar_deleting_destroy_dxt_base`

Native target: `grim.dll` at `0x1001aec8` (28 bytes).

This VC6 scalar deleting wrapper occupies the shared DXT base vtable. Unlike
the derived DXT1-DXT5 wrapper, it calls the regular destructor directly rather
than through the linker-emitted tail thunk.
