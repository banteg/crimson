# grim_set_color_slot

Native target: `grim.dll` at `0x100081c0` (109 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 27/27
normalized instructions, full prefix, and masked references `9/0/0`.

## Recovered source shape

- The vtable slot and `retn 0x14` establish a C++ `__thiscall` member taking an
  integer index and four float channels. The body does not otherwise read
  `this`.
- The channels are multiplied by 255, converted through the native x87
  `_ftol` path, masked to their low bytes, and packed as ARGB. Unlike
  `grim_set_color`, this indexed setter performs no alpha or RGB clamping.
- The packed value is written directly to `grim_color_slot0[index]`. Native
  code performs no range check, so callers are responsible for indices 0..3.
- The array layout is independently consumed by the exact quad renderer
  reconstructions and produced by both exact all-slot color setters.

No inline assembly, dummy references, or layout-only branches are used.
