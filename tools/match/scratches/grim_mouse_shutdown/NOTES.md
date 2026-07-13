# grim_mouse_shutdown

Native target: `grim.dll` at `0x1000a7d0..0x1000a80e` (62 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 19/19
normalized instructions, full prefix, and masked references `5/0/0`.

## Recovered source shape

- If the mouse device exists, the function calls its DirectInput `Unacquire`
  slot, calls the inherited COM `Release` slot, and nulls the global device
  pointer.
- It independently checks the parent DirectInput interface, calls its
  `Release` slot, and nulls that global pointer.
- The ordinary source is structurally identical to keyboard shutdown with the
  mouse globals substituted. Both methods use their x86 `__stdcall` ABI and
  native vtable offsets (`0x20` and `0x08`).

No inline assembly, volatile state, fake reference, forced address, or
layout-only control flow is used.
