# input_detect_active_analog_axis

Native target: `crimsonland.exe` at `0x448b50` (377 bytes).

The helper probes the six analog configuration channels in this exact order:
`0x13f`, `0x140`, `0x141`, `0x153`, `0x154`, and `0x155`. It clears each
sample's IEEE-754 sign bit and returns the first channel whose magnitude is
greater than `0.5f`. If no channel is active, it flushes pending input through
`IGrim2D_cpp::grim_flush_input()` and returns zero.

The recovered source preserves all calls, channel IDs, comparisons, early
returns, and the no-hit flush. The six magnitude tests use the same small
inlined `abs_bits(float)` helper recovered in the game's angular math. Each
expansion owns a short-lived integer bit view, so VC6 emits the native
immediate `0x7fffffff` mask at every test instead of hoisting one mask into a
saved register.

The result is an exact 103/103-instruction, 377/377-byte match with all 13
native references aligned. The helper is ordinary reusable source shape; no
dummy dependency, volatile qualifier, fake reference, or register constraint
is used.
