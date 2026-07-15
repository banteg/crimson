# `console_render`

Native target: `crimsonland.exe` at `0x00401dd0` (1,408 bytes).

Live callsites load `console_log_queue` into `ECX` and pass no stack
arguments, identifying this as `console_queue_t::render()`. The recovered
method draws the sliding translucent background and border, configures the
font renderer, emits the version label and input prompt, walks the scrolled
log chain, and draws a sine-squared blinking caret in either mono or small-font
mode.

The natural VC6 reconstruction has the same 400-instruction extent and a
94.75% order-sensitive score. All 61 aligned references resolve. The remaining
code delta is register allocation: native keeps the visible-line count in
`EBP` and the text Y coordinate or temporary vtable in `EBX`, while the current
source assigns those two roles in the opposite order. The only non-register
spelling difference is native `add eax, -2` versus candidate `sub eax, 2` when
recomputing the visible-line bound.

The background and border reuse one ordinary two-float position and one
four-float color value, which reproduces the native 28-byte local frame. The
caret width call is kept directly inside the small-font draw expression so
VC6 preserves the native right-to-left argument evaluation. The second
visible-line calculation is expressed as a minimum starting from `log_count`,
matching the native instruction count and data flow.

Reference auditing also proves that the caret pulse raises `sin(time * 3)` to
the eighth power before applying the `0.2` floor. This corrects the earlier
quadratic interpretation in the Python port and is covered there by a focused
regression test.

The `msvc6.5pp` and `/G6` alternatives both regress materially. No inline
assembly, volatile state, dummy references, dead expressions, forced register
variables, or artificial ordering constraints are used.
