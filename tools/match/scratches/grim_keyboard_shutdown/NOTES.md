# grim_keyboard_shutdown

Native target: `grim.dll` at `0x1000a550..0x1000a58e` (62 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 19/19
normalized instructions, full prefix, and masked references `5/0/0`.

## Recovered source shape

- If the keyboard device exists, the function calls its DirectInput
  `Unacquire` slot, calls the inherited COM `Release` slot, and nulls the
  global device pointer.
- It then independently checks the parent DirectInput interface, calls its
  `Release` slot, and nulls that global pointer.
- Both COM methods use their native x86 `__stdcall` ABI. The compact local
  vtable declarations expose only the slots needed to express those ordinary
  calls and preserve their real offsets (`0x20` and `0x08`).

No inline assembly, volatile state, fake reference, forced address, or
layout-only control flow is used.
