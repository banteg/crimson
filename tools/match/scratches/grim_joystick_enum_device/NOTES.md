# grim_joystick_enum_device

Native target: `grim.dll` at `0x1000a110..0x1000a142` (50 bytes).

Live Binary Ninja identifies the standard `EnumDevices` callback shape. It
uses the instance GUID at offset 4 to create a device, returns continue (`1`)
on failure, and otherwise sets `grim_joystick_found` and stops enumeration
(`0`). Natural C++ matches all 16 VC6.5 instructions, full prefix, and
references `3/0/0` without shaping constructs.
