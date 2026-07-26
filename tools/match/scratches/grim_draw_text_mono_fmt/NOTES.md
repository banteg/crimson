# grim_draw_text_mono_fmt

Native target: `grim.dll` at `0x10009940` (52 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 16/16
normalized instructions, full prefix, and masked references `3/0/0`.

## Recovered source shape

- This printf-style varargs member receives an explicit stack `self` under the
  cdecl member ABI and returns with plain `ret`.
- `va_start` selects the argument tail after `fmt`, and the imported
  `vsprintf` writes into the shared `grim_printf_buffer` buffer.
- The wrapper then calls `grim_draw_text_mono(x, y, buffer)` through vtable
  slot `0x13c`; the wrapper itself occupies slot `0x140`.
- Live Binary Ninja disassembly identifies both buffer operands and the
  `vsprintf` IAT call at `0x1004c0b4`. The EXE has 3 static calls in 3
  functions.

No inline assembly, dummy references, or layout-only branches are used.
