# grim_is_key_down

Native target: `grim.dll` at `0x10007320` (16 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 5/5
normalized instructions, full prefix, and masked references `1/0/0`.

## Recovered source shape

- Static callers establish a C++ vtable member with `this` in `ECX`, one key
  argument, callee cleanup via `retn 4`, and a byte result consumed through
  `AL`.
- The body simply forwards to the exact `grim_keyboard_key_down` helper and
  therefore inherits its low-byte key aliasing and 0/1 result.
- Keeping both source returns byte-sized is material: `int` adds a zero extend,
  while native C++ `bool` adds normalization after the helper call.

No inline assembly, volatile state, dummy reference, forced address, or
ABI-equivalent flat shim is used.
