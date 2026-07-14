# ui_draw_progress_bar

Native target: `crimsonland.exe` at `0x0041a6d0` (237 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 66/66
normalized instructions, full prefix, and masked references `11/0/0`.

## Recovered source shape

- The ratio is clamped to `[0.0, 1.0]` with the native signed x87 comparison
  behavior.
- The four-component background color is a constructed value containing
  `(r * 0.6, g * 0.6, b * 0.6, a * 0.4)`. Modeling it as four unrelated array
  assignments changes VC6's evaluation order; the value constructor exactly
  reproduces the native stores.
- A constructed two-float position is used for the background rectangle at
  `(xy, width, 4)`. Its ordinary inlined `set` method updates the position to
  `(xy.x + 1, xy.y + 1)` before drawing the foreground at
  `((width - 2) * ratio, 2)` with the caller's color.

No inline assembly, volatile state, dummy dependencies, forced addresses, or
layout-only control flow is used.
