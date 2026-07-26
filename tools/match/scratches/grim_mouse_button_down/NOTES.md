# grim_mouse_button_down

Native target: `grim.dll` at `0x1000a590` (14 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 4/4
normalized instructions, full prefix, and masked references `1/0/0`.

## Recovered source shape

- The helper indexes `DIMOUSESTATE2.rgbButtons` directly with the supplied
  button number; native code performs no bounds check.
- It shifts the selected byte right by seven and returns the resulting 0/1
  byte. A named byte local with `>>=` preserves the native byte-width operation
  without widening.

No inline assembly, volatile state, dummy reference, forced address, or
layout-only expression is used.
