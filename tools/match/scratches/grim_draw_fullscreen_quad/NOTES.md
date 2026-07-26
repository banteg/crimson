# grim_draw_fullscreen_quad

Native target: `grim.dll` at `0x10007870` (109 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 32/32
normalized instructions, full prefix, and masked references `2/0/0`.

## Recovered source shape

- The apparent no-argument prototype was stale. The sole EXE caller pushes
  zero, and the native method returns with `retn 0x4`; the recovered member
  therefore retains one unused integer parameter.
- The method clears rotation, begins a batch, draws the current texture from
  `(0, 0)` to the backbuffer dimensions, and ends the batch.
- The stored dimensions are signed integers but are explicitly cast through
  unsigned before float conversion. This ordinary source shape produces the
  native qword `fild` stack schedule.
- `evidence_summary.json` records 6,902 entry/exit events and 3,451 batch
  pairs. The EXE has one static callsite.

No inline assembly, volatile state, dummy references, ABI shim, or layout-only
expressions are used.
