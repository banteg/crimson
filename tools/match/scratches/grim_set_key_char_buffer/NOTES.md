# grim_set_key_char_buffer

Native target: `grim.dll` at `0x10005c20` (32 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 7/7
normalized instructions, full prefix, and masked references `3/0/0`.

## Recovered source shape

- The member stores the supplied buffer pointer, count pointer, and capacity
  into three adjacent globals at `0x10053048..0x10053050`.
- It performs no validation, allocation, or initialization; the caller owns
  the storage and count. The window-message path later enforces capacity and
  appends a terminating NUL.
- Three direct assignments naturally recover the native argument loads,
  global stores, and `retn 0xc`; `this` is unused.

No inline assembly, volatile state, dummy reference, forced address, aggregate
anchor, or ABI-equivalent flat shim is used.
