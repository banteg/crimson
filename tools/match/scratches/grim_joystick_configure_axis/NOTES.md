# grim_joystick_configure_axis

Native target: `grim.dll` at `0x1000a150..0x1000a1b3` (99 bytes).

The `EnumObjects` callback filters DirectInput axis objects with `dwType & 3`
and applies a 24-byte `DIPROPRANGE` by object ID: minimum `-1000`, maximum
`1000`. It stops enumeration only when `SetProperty(DIPROP_RANGE)` fails.
Natural C++ matches all 26 VC6.5 instructions, full prefix, and references
`1/0/0` without shaping constructs.
