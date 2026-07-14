# console_command_find

Native target: `crimsonland.exe` at `0x00402750` (93 bytes).

The method walks the command list and returns the first node whose name is
equal to the query. The recovered 12-byte node contains `name`, `next`, and a
zero-argument handler. Natural C++ matches all 47 instructions with no masked
reference debt.
