# grim_joystick_poll

Native target: `grim.dll` at `0x1000a2b0..0x1000a307` (87 bytes).

The poller first calls the device `Poll` method. On failure it retries
`Acquire` only while the result is `DIERR_INPUTLOST`, then returns false for
that frame. On success it requests the full 272-byte `DIJOYSTATE2` and returns
whether `GetDeviceState` succeeded.

Natural C++ matches all 32 VC6.5 instructions, full prefix, and references
`5/0/0`. The explicit final success/failure branch is source-significant: it
reproduces the native byte return without a fabricated cast or register hint.
