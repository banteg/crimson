# grim_submit_vertices_transform_color

Native target: `grim.dll` at `0x100084e0` (218 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 72/72
normalized instructions, full prefix, and masked references `10/0/0`.

## Recovered source shape

- A render-disabled guard encloses the copy, transform loop, count update, and
  capacity check.
- `memcpy` copies `count * 0x1c` bytes into the current batch. Positive counts
  enter the seven-dword-stride matrix and offset loop.
- Scalar rotation accumulators recover the native x87 order for both output
  coordinates before the supplied XY translation is applied.
- Dword field 4 is overwritten through an integer pointer with one packed
  color. This corrects the earlier float-pointer prototype without relying on
  a bit-preserving float faketype.
- Static callers span both UI and effect rendering, while the checked-in UI
  trace records 7,202 transform-color submissions.
- The low-word batch count and capacity-triggered virtual flush match the
  other three recovered submitters.

No inline assembly, dummy references, or layout-only branches are used.
