# grim_draw_rect_outline

Native target: `grim.dll` at `0x10008f10` (356 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 125/125
normalized instructions, full prefix, and masked references `8/0/0`.

## Recovered source shape

- The method unbinds texture stage 0, switches color and alpha operations from
  `MODULATE` to `SELECTARG2`, and restores both operations after drawing.
- Rotation is cleared before beginning one explicit batch.
- Unit-height and unit-width rectangles each take a single-quad fast path.
  Other rectangles draw four edge quads in top, left, bottom, right order; the
  bottom width is extended by one pixel.
- Live Binary Ninja shows `this` in `ECX`, three stack arguments, and
  `retn 0xc`. The checked-in UI trace contains 3,132 calls, and the EXE has 12
  static calls across 11 functions.

No inline assembly, dummy references, or layout-only branches are used.
