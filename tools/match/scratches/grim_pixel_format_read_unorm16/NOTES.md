# `grim_pixel_format_read_unorm16`

Native target: `grim.dll` at `0x1001a1be` (112 bytes).

D16_LOCKABLE and L16 share this vtable reader. It walks one addressed row of
unsigned 16-bit samples, expands each through the native `1/65535` scale into
equal RGB floats, sets alpha to one, and applies the active color key.
