# console_register_command

Native target: `crimsonland.exe` at `0x004026e0` (99 bytes).

The recovered command-node constructor duplicates the supplied name and
zeroes both `next` and `handler`. The method then installs the caller's handler
and appends the node to the list, initializing an empty head when necessary.
Natural C++ matches all 38 instructions and references `2/0/0`.
