# console_log_node_free

Native target: `crimsonland.exe` at `0x004011f0` (68 bytes).

This member-style release primitive owns an eight-byte linked node. It frees
the node text, clears it, recursively releases the tail, clears the link, and
optionally frees `this` when bit zero of `free_self` is set. It returns the
original node pointer in `EAX`, matching the classic VC6 scalar-deleting
destructor ABI used by the surrounding `delete` expressions.

The recovered method matches all 24 instructions, full prefix, with both
native references aligned. The same body services structurally identical log
and history chains.
