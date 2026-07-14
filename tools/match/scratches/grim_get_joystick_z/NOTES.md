# grim_get_joystick_z

Native target: `grim.dll` at `0x100075a0`.

Returns `DIJOYSTATE2.lZ` directly. Natural C++ matches all 2 instructions,
full prefix, and references `1/0/0` with MSVC 6.5.
