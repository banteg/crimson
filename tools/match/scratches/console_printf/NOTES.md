# console_printf

Native target: `crimsonland.exe` at `0x00401870` (49 bytes).

This variadic `void` helper does nothing when console echo is disabled.
Otherwise it formats into the shared 512-byte buffer and passes the result to
the queue's `void` line-insertion method. The byte that decompilers display as
a return value is incidental `AL` state from the echo check or callee.

The corrected source type retains the exact 17/17-instruction match with all
four references aligned. `crimsonland_gameplay.h` now carries the same `void`
declaration instead of propagating the incidental `AL` state to gameplay
scratches.
