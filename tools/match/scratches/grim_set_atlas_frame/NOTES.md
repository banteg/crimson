# grim_set_atlas_frame

Native target: `grim.dll` at `0x10008230` (139 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 31/31
normalized instructions, full prefix, and masked references `15/0/0`.

## Recovered source shape

- `atlas_size` indexes `grim_subrect_ptr_table`; `frame` selects one
  two-float origin from that table.
- The method initializes all four current UV corners from the origin, then
  advances the two right-edge U coordinates and two bottom-edge V coordinates
  by one atlas cell (`1 / atlas_size`).
- Chained record initialization and paired U assignment naturally recover the
  native store order. The two V `+=` operations preserve the native x87
  load/add/store sequence and final x87 stack pop.
- Live Binary Ninja confirms `ECX=this`, two stack parameters, and `retn 0x8`.
  The EXE contains 25 static callsites across six functions.

No inline assembly, volatile state, dummy references, ABI shim, fake type, or
layout-only expression is used.
