# `grim_pixel_format_ctor_r8g8b8`

Native target: `grim.dll` at `0x1001a428` (28 bytes).

This derived pixel-format constructor delegates `(desc, 24, 1)` to the common
format base, installs the R8G8B8 vtable, and returns `this`. The source uses a
normal C++ base initializer and compiler-generated vtable store.
