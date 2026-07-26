# grim_submit_vertices_offset_color

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
