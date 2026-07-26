# grim_is_mouse_button_down

Native target: `grim.dll` at `0x10007410` (38 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 11/11
normalized instructions, full prefix, and masked references `3/0/0`.

## Recovered source shape

- Live vtable callers establish a C++ member with one button argument and a
  byte-sized 0/1 result.
- When input caching is enabled, the member returns the selected cached button
  byte. Otherwise it calls `grim_mouse_button_down`, which reads the live
  `DIMOUSESTATE2` buffer.
- The recovered member source replaces the earlier ABI-equivalent flat
  `__stdcall` scratch while preserving the exact native instructions.

No inline assembly, volatile state, dummy reference, forced address, or
layout-only control flow is used.
