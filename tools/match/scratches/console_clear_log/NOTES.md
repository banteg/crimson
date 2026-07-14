# console_clear_log

Native target: `crimsonland.exe` at `0x004011a0` (78 bytes).

The clear command deletes the owned log chain and then resets the head, entry
count, and scroll offset. A natural `delete` with the recovered inline node
destructor reproduces the native outer cleanup and recursive tail-release call.

The result matches all 28 instructions, full prefix, with all seven references
aligned. The static CRT's scalar `operator delete` resolves to the same native
free body used by explicit string releases.
