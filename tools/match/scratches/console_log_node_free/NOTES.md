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

The selected object now emits both true member identities:
`console_log_node_t::release` and `console_history_entry_t::release`. Live
xrefs to `0x004011f0` include both delete paths in `console_destroy`
(`0x00401708` and `0x00401783`), and each record is exactly two owned pointers.
The history implementation uses its real `line`/`next` fields rather than an
alias; link-time folding can coalesce the identical code while the configured
log-node method remains 24/24 with `2/0/0` references.
