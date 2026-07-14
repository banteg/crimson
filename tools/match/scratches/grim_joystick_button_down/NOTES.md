# grim_joystick_button_down

Native target: `grim.dll` at `0x1000a310` (19 bytes).

The helper indexes `DIJOYSTATE2.rgbButtons` by the low byte of its argument,
then returns bit 7 as an unsigned byte. Natural C++ matches all 5 instructions,
full prefix, and references `1/0/0` with MSVC 6.5. The byte return explains why
the public vtable wrapper forwards `AL` without boolean or integer widening.
