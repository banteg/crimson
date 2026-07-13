# grim_submit_vertices_offset

Native target: `grim.dll` at `0x10008680` (153 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 50/50
normalized instructions, full prefix, and masked references `8/0/0`.

## Recovered source shape

- A render-disabled guard returns before any copy or counter update.
- `memcpy` copies `count * 0x1c` bytes from the caller's generic seven-float
  vertex stream into the current batch pointer. VC6 lowers this ordinary copy
  to the native `rep movsd`/`rep movsb` sequence.
- For a positive count, a local float pointer adjusts X/Y by the supplied
  two-float offset, while the global write pointer advances seven floats per
  vertex. Nonpositive counts skip only the adjustment loop.
- The method adds the truncated count to the batch counter's low 16 bits and
  flushes through virtual slot `0xec` once capacity is reached.

No inline assembly, dummy references, or layout-only branches are used.
