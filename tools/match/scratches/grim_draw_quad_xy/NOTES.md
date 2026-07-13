# grim_draw_quad_xy

Native target: `grim.dll` at `0x10008720` (34 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 14/14
normalized instructions, full prefix, and no masked-reference debt.

## Recovered source shape

- Live Binary Ninja disassembly and `retn 0xc` establish a C++ `__thiscall`
  member taking an XY pointer, width, and height.
- The method is a direct adapter: it loads `xy[0]` and `xy[1]`, preserves width
  and height, and forwards all four floats to virtual slot `0x11c`, the exact
  `grim_draw_quad` reconstruction.

No inline assembly, dummy references, or layout-only branches are used.
