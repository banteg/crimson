# grim_set_mouse_pos

Native target: `grim.dll` at `0x10007530`.

The method writes the supplied bit patterns to both the accumulated and
cached X/Y globals. Natural C++ matches all 9 instructions, full prefix, and
references `4/0/0` with the stock MSVC 6.5 profile.
