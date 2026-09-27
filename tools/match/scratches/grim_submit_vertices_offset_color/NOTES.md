# grim_submit_vertices_offset_color

## Plausibility pass (2026-09-27)

The countdown became an indexed loop, and the offset add goes through a small `grim_translate_point` helper shared with the transform submitters. Its single-use `x`/`y` locals are FROUND owners that give native's operand order. The packed color is stored through a named `unsigned long *vertex`, and the write pointer has the same `float *` type as its siblings. The source stays exact, byte for byte. See [the Grim audit](../../PLAUSIBILITY-AUDIT-GRIM-2026-09-27.md). Any older description below of the replaced spelling is historical.

Native target: `grim.dll` at `0x10008430` (168 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 54/54
normalized instructions, full prefix, and masked references `9/0/0`.

## Recovered source shape

- A render-disabled guard returns before any copy or counter update.
- `memcpy` copies `count * 0x1c` bytes from the caller's generic seven-dword
  vertex stream into the batch. Positive counts then enter the adjustment
  loop.
- Local X/Y temporaries preserve the native x87 operand order while adding the
  supplied offset. The method overwrites dword field 4 with one packed color
  and advances the global pointer by seven dwords per vertex.
- Native integer loads/stores establish that the final argument is a pointer to
  packed 32-bit color, correcting the earlier float-pointer prototype.
- The low-word count update and capacity-triggered flush match the offset-only
  sibling.

No inline assembly, dummy references, or layout-only branches are used.
