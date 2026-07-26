# grim_set_sub_rect

Native target: `grim.dll` at `0x100082c0` (143 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 31/31
normalized instructions, full prefix, and masked references `15/0/0`.

## Recovered source shape

- `atlas_size` indexes `grim_subrect_ptr_table`; `frame` selects one
  two-float origin from that table.
- The method initializes all four current UV corners from the origin. It then
  advances the two right-edge U coordinates by `width / atlas_size` and the
  two bottom-edge V coordinates by `height / atlas_size`.
- The chained record initialization and paired U assignment naturally recover
  the native store order. The two V `+=` operations preserve the native x87
  duplicate-and-add sequence while directly expressing the rectangle update.
- Live Binary Ninja confirms `ECX=this`, four stack parameters, and `retn 0x10`.
  Static callers include the HUD, bonus renderer, and text-input renderer; a
  recovered call uses `(8, 2, 1, frame << 1)`.

No inline assembly, volatile state, dummy references, ABI shim, fake type, or
layout-only expression is used.
