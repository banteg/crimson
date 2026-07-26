# grim_was_mouse_button_pressed

Native target: `grim.dll` at `0x10007440` (131 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 51/51
normalized instructions, full prefix, and masked references `7/0/0`.

## Recovered source shape

- The result is the current down state AND the prior release latch. The latch
  is then updated to the inverse of a second state query, so a held button
  produces only one event until released.
- Non-cached mode intentionally dispatches `grim_is_mouse_button_down` twice
  through vtable slot `0x58`. Cached mode applies the same short-circuit logic
  directly to the 16-byte cache and latch arrays.
- The member returns a byte-sized C++ boolean and removes its single argument
  with `retn 4`; the body otherwise uses `this` only for virtual dispatch.

No inline assembly, volatile state, dummy reference, forced address, or
layout-only control flow is used.
