# grim_apply_settings

`grim_apply_settings` is an eight-byte `__thiscall` wrapper at `0x10006020`.
The native body calls `grim_run_loop` at `0x10003c00`, writes `1` to `AL`,
and returns. The explicit byte-sized return establishes a C++ `bool` result;
the sole Crimsonland call site ignores it.

Live Binary Ninja evidence shows that `grim_run_loop` owns the Win32 message
pump, input polling, device-loss handling, frame callback, and Direct3D
presentation loop. It has no prepared call arguments at this wrapper. Its
previous inferred register parameters are analysis artifacts from values that
remain live in registers.

The recovered source matches all three native instructions and the call
reference under MSVC 6.5 `/O2 /GB`.
