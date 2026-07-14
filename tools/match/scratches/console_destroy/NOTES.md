# console_destroy

Native target: `crimsonland.exe` at `0x004016e0` (187 bytes).

This is the natural `console_queue_t` destructor. It deletes the log chain,
releases the owned name and node for the current cvar and command heads, then
deletes the history chain. Each queue owner pointer is cleared after release.
The cvar and command nodes intentionally do not recursively own their `next`
pointers; log and history nodes do.

Inline destructors plus ordinary `delete` expressions match all 77 native
instructions, full prefix, with all ten references aligned.
