# grim_is_joystick_button_down

Native target: `grim.dll` at `0x100075c0`.

The byte-returning interface method forwards its integer argument to
`grim_joystick_button_down`. Natural C++ matches all 5 instructions, full
prefix, and the call reference `1/0/0` with MSVC 6.5.
