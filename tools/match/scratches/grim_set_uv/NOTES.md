# grim_set_uv

Native target: `grim.dll` at `0x10008350` (74 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 17/17
normalized instructions, full prefix, and masked references `8/0/0`.

## Recovered source shape

- The vtable slot and `retn 0x10` epilogue establish a C++ `__thiscall` member
  with four float arguments. The method does not otherwise need to read
  `this`.
- The four inputs describe the opposite corners of a UV rectangle. Eight
  ordinary field assignments expand them clockwise into `(u0,v0)`, `(u1,v0)`,
  `(u1,v1)`, and `(u0,v1)`.
- The destination is the same contiguous four-element UV array consumed by the
  exact `grim_draw_quad` and `grim_draw_quad_points` reconstructions.

No inline assembly, dummy references, or layout-only branches are used.
