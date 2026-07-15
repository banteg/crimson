# `ui_button_update`

Native target: `crimsonland.exe` at `0x0043e830` (1215 bytes).

Live Binary Ninja body and callsite evidence recovers the shared button
controller and renderer: focus decoration, lazy narrow/wide texture lookup,
label-dependent width, pointer focus, hover/click animation, highlight and
plate drawing, centered text, keyboard or pointer activation, and the UI click
sound.

Exact verified match: 100.00%, with 347/347 normalized instructions and masked
references `61/0/0`, using Microsoft Visual C++ 6.5 with
`/O2 /GB /W3 /GR-`.

## Recovered source shape

- The original byte-sized state members have C++ `bool` semantics. In
  particular, returning `activated` directly returns its byte in `AL`; treating
  the field only as an arbitrary byte makes VC6 emit a normalization tail.
- Activation is one boolean assignment when the button is enabled. This
  naturally reproduces the native true/false lowering and avoids VC6 reserving
  `EBX` as a shared zero register.
- The click tint uses the common `0.001f` animation scale multiplied by `0.5f`
  for red/green and `0.7f` for blue. The folded blue coefficient is therefore
  the native `0x3a378035`, one ULP above a standalone `0.0007f` literal.
- Separate hovered/non-hovered text-color calls and an intermediate normalized
  hover-alpha term reproduce the native virtual-call and x87 evaluation order.

The source uses no inline assembly, volatile state, dummy references, dead
expressions, or artificial ordering constraints. The fakematch validator
passes.
