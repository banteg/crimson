# grim_draw_fullscreen_color

Native target: `grim.dll` at `0x100079b0` (259 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 83/83
normalized instructions, full prefix, and masked references `8/0/0`.

## Recovered source shape

- Non-positive alpha returns without changing D3D or batch state.
- Positive alpha unbinds texture stage 0 and switches color and alpha
  operations from `MODULATE` to `SELECTARG2` before forwarding all four RGBA
  scalars to `grim_set_color`.
- Rotation is cleared, one batch draws a quad from `(0, 0)` to the backbuffer
  width and height, and the normal modulate operations are restored.
- The backbuffer dimensions are unsigned integers. Their ordinary float casts
  produce the native qword `fild` schedule without source-shaping helpers.
- Live Binary Ninja confirms four stack floats and `retn 0x10`.
  `evidence_summary.json` records 60 calls, and the EXE has 2 static calls in 2
  functions.

No inline assembly, volatile state, dummy references, or layout-only
expressions are used.
