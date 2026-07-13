# grim_draw_rect_filled

Native target: `grim.dll` at `0x100078e0` (205 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 72/72
normalized instructions, full prefix, and masked references `6/0/0`.

## Recovered source shape

- Live Binary Ninja disassembly corrects the prior three-argument prototype.
  The method receives `this` in `ECX`, four stack arguments, and returns with
  `retn 0x10`; the fourth argument is an RGBA float pointer whose alpha is
  tested before drawing.
- Positive alpha enters a self-contained D3D8 state wrapper: texture stage 0
  is unbound, color and alpha operations switch from `MODULATE` to
  `SELECTARG2`, and both operations are restored after the draw.
- The method forwards the RGBA pointer to `grim_set_color_ptr`, clears
  rotation, begins a batch, draws one quad from `xy`, width, and height, and
  ends the batch.
- The D3D8 calls use their ordinary COM interface and documented enum values.
  Two local compatibility aliases only bridge names missing from the bundled
  VC6 Platform SDK; they do not affect emitted code.

No inline assembly, dummy references, or layout-only branches are used.
