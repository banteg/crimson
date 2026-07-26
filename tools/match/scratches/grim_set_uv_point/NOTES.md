# grim_set_uv_point

Native target: `grim.dll` at `0x100083a0` (29 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 6/6
normalized instructions, full prefix, and masked references `2/0/0`.

## Recovered source shape

- The vtable slot and `retn 0xc` establish a C++ `__thiscall` member taking an
  integer index and two floats. The body does not otherwise read `this`.
- Two ordinary field assignments write U and V through the eight-byte
  `GrimUV` stride independently recovered by `grim_set_uv` and both exact quad
  renderers.
- Native code performs no index bounds check, so callers are responsible for
  indices 0..3.

No inline assembly, dummy references, or layout-only branches are used.
