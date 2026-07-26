# grim_joystick_up_active

Native target: `grim.dll` at `0x10006ea0`.

The helper snapshots the Y deadzone and center, reads the current Y axis
through Grim2D vtable slot `0x9c`, and returns whether the centered value is
strictly below `-deadzone`. Natural C++ matches all 23 instructions, full
prefix, and references `3/0/0` with MSVC 6.5.
