# console_push_line

Native target: `crimsonland.exe` at `0x004017a0` (193 bytes).

When console echo is enabled, this method caps the log at 4096 entries by
walking to and deleting the oldest tail, then prepends a newly allocated copy
of the incoming line. The constructor clears `next` before `text`, matching the
native initialization schedule. The entry count is decremented on eviction and
incremented after insertion.

The method is `void`: the apparent byte result in decompiler output is merely
the last value left in `AL`. That source type matches all 68 instructions,
full prefix, with all five references aligned and also preserves the existing
exact `console_printf` caller.
