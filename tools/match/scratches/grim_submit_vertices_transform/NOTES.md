# grim_submit_vertices_transform

Native target: `grim.dll` at `0x100085c0` (192 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 64/64
normalized instructions, full prefix, and masked references `9/0/0`.

## Recovered source shape

- A render-disabled guard encloses the entire copy, transform, count update,
  and capacity check.
- `memcpy` copies `count * 0x1c` bytes into the current batch. Only positive
  counts enter the seven-dword-stride adjustment loop.
- Scalar rotation accumulators recover the native x87 sequence for
  `x' = y*m[1] + x*m[0]` and `y' = y*m[3] + x*m[2]`; the results are then
  translated by the supplied XY offset.
- The global write pointer advances once per transformed vertex. The method
  finally updates the low 16 bits of the batch count and flushes through the
  virtual `0xec` slot when capacity is reached.
- The checked-in UI trace records 13,940 transform submissions, making this a
  high-coverage native path rather than an unused wrapper.

No inline assembly, dummy references, or layout-only branches are used.
