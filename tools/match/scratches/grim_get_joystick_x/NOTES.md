# grim_get_joystick_x

Native target: `grim.dll` at `0x10007580`.

Returns `DIJOYSTATE2.lX` directly. Natural C++ matches all 2 instructions,
full prefix, and references `1/0/0` with MSVC 6.5.
