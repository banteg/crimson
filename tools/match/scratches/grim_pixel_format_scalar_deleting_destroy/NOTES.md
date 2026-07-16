# `grim_pixel_format_scalar_deleting_destroy`

Native target: `grim.dll` at `0x1001ae58` (28 bytes).

This is the compiler-generated scalar deleting destructor shared by the 30
ordinary pixel-format vtables. It invokes the common converter destructor and
conditionally releases `this` when the deleting flag is set.
