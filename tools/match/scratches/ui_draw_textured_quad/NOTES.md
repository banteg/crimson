# ui_draw_textured_quad

Native target: `crimsonland.exe` at `0x00417ae0` (158 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 46/46
normalized instructions, full prefix, and masked references `6/0/0`.

## Recovered source shape

- Static IDA call sites and the native stack loads establish the actual ABI as
  `(x, y, width, height, texture_id)`. The prior decompiler-derived map put the
  texture first; the map is corrected with the call-site-proven order.
- The helper binds the fifth argument on texture stage zero, selects the full
  UV rectangle, sets config variable `0x15` to one, and converts the first four
  integer arguments to floats for `grim_draw_quad`.
- It ends the batch and restores config variable `0x15` to two.

No inline assembly, dummy references, forced addresses, or layout-only control
flow is used.
