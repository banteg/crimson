# grim_draw_text_small_fmt

Native target: `grim.dll` at `0x10009980` (52 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 16/16
normalized instructions, full prefix, and masked references `3/0/0`.

## Recovered source shape

- This printf-style varargs member uses the cdecl member ABI. The native
  function receives `self`, `x`, `y`, and `fmt` on the stack and returns with a
  plain `ret` rather than a fixed-argument `__thiscall` stack pop.
- `va_start` points immediately after `fmt`, and the imported `vsprintf` writes
  into the shared `grim_printf_buffer_alt` buffer.
- The wrapper then calls `grim_draw_text_small(x, y, buffer)` through vtable
  slot `0x144`; the wrapper itself occupies slot `0x148`.
- The reference catalog proves the buffer operands and the `vsprintf` IAT entry
  at `0x1004c0b4`. The EXE has 86 static calls across 15 functions.

No inline assembly, dummy references, or layout-only branches are used.
