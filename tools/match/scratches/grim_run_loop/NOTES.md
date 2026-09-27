# grim_run_loop

## Plausibility pass (2026-09-27)

The guarded `do`/`while` main loop became `if (grim_main_window_hwnd != 0)` around `while (msg.message != WM_QUIT)`; loop inversion supplies the guard. The key-repeat decay indexes `grim_key_repeat_timers[i]` directly instead of through a field pointer. The source stays exact, byte for byte. See [the Grim audit](../../PLAUSIBILITY-AUDIT-GRIM-2026-09-27.md). Any older description below of the replaced spelling is historical.

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
Its C linkage preserves the native `_grim_run_loop` entry symbol used by the
application seam.
