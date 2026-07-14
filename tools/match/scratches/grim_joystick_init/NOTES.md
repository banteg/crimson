# grim_joystick_init

Native target: `grim.dll` at `0x1000a1c0..0x1000a2a7` (231 bytes).

The initializer lazily creates DirectInput8, enumerates attached game
controllers, installs `c_dfDIJoystick2`, uses cooperative flags `5`, configures
every axis through `grim_joystick_configure_axis`, acquires the created device,
and performs an initial poll. As in the keyboard and mouse paths, a null window
causes `GetDesktopWindow` to be called without assigning its return value.

Natural C++ matches all 90 VC6.5 instructions, full prefix, and references
`19/0/0`. No custom compiler flags or shaping constructs are used.
