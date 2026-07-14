# console_history_apply

Native target: `crimsonland.exe` at `0x4018d0` (99 bytes).

This `console_queue_t` method walks the singly linked history list up to
`history_index - 1`, clamps the index when it reaches the end of the list,
copies the selected command into the 1024-byte console input buffer, refreshes
the cursor from the copied string length, and clears the ready flag for editing.

The member offsets reveal `history_head` at `0x10` and `history_index` at
`0x14`; retaining `open` at `0x28` keeps the already matched console layout
consistent. The canonical `for` traversal matches all 42 instructions and all
4 native references exactly, including VC6's inlined `strcpy` and `strlen`.
