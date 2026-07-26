# grim_joystick_left_active

Native target: `grim.dll` at `0x10006f40`.

The helper snapshots the X deadzone and center, reads the current X axis
through Grim2D vtable slot `0x98`, and returns whether the centered value is
strictly below `-deadzone`. Natural C++ matches all 23 instructions, full
prefix, and references `3/0/0` with MSVC 6.5.
