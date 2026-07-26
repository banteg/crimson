# grim_run_loop

`grim_run_loop` at `0x10003c00` owns the Win32 message pump, input sampling,
lost-device recovery, per-frame callback, presentation, and orderly runtime
shutdown. The initial timing sequence and 30 ms `MyApp` pump are preserved as
observed in the native body.

When no message is pending, active frames decay all 256 key-repeat timers,
poll joystick and uncached mouse state, and publish the joystick buffer. The
loop tests cooperative level before rendering, sleeps and retries a lost
device, invokes the one-shot restore callback, exits when the frame callback
returns false, updates the optional input provider, and presents unless
rendering is disabled. Frozen non-DC frames sleep for 50 ms.

The recovered function matches all 174 native instructions and all 61 masked
references across its 608-byte body under MSVC 6.5 `/O2 /GB`.
