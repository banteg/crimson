# grim_joystick_shutdown

Native target: `grim.dll` at `0x1000a330..0x1000a36e` (62 bytes).

The shutdown path unacquires and releases the joystick device, nulls it, then
releases and nulls the parent DirectInput interface. Natural C++ matches all
19 VC6.5 instructions, full prefix, and references `5/0/0`, mirroring the
already recovered keyboard and mouse teardown shape.
