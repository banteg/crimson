# grim_get_joystick_pov

Native target: `grim.dll` at `0x100075b0`.

Returns `DIJOYSTATE2.rgdwPOV[index]` without a bounds check. Natural C++
matches all 3 instructions, full prefix, and references `1/0/0` with MSVC 6.5.
