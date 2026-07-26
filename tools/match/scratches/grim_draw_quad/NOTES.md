# grim_draw_quad

Native target: `grim.dll` at `0x10008b10` (800 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 195/195
normalized instructions, full prefix, and masked references `68/0/0`.

## Recovered source shape

- Live Binary Ninja callsites and the `retn 0x10` epilogue establish a C++
  `__thiscall` member with `this` in `ECX`, rather than the provisional flat C
  signature. The method dispatches batch begin and flush through vtable slots
  `0xe8` and `0xec`.
- The zero-rotation path emits the four axis-aligned corners. The rotated path
  keeps a fifth point as the center and uses an inlined one-step Quake inverse
  square root to approximate half the diagonal. `grim_set_rotation` has already
  biased the cached sine and cosine by pi/4.
- Position, Z/RHW, and UV values are copied as adjacent two-float aggregates;
  color remains one packed 32-bit word. Those fields produce the native
  28-byte vertex stride without padding. Four explicit aggregate writes recover
  the DLL's exact load/store schedule.
- The batch counter is genuinely maintained through its low 16 bits. After
  four vertices, the write pointer advances by `0x70` and the method flushes
  when the zero-extended count reaches the configured capacity.

The inverse-square-root helper and grouped vertex fields are semantic source
reconstructions supported by the native x87 and copy sequences. No inline
assembly, dummy references, or layout-only branches are used.
