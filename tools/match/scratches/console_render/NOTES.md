# `console_render`

Native target: `crimsonland.exe` at `0x00401dd0` (1,408 bytes).

Live callsites load `console_log_queue` into `ECX` and pass no stack
arguments, identifying this as `console_queue_t::render()`. The recovered
method draws the sliding translucent background and border, configures the
font renderer, emits the version label and input prompt, walks the scrolled
log chain, and draws a sine-squared blinking caret in either mono or small-font
mode.

The natural VC6 reconstruction has the same 400-instruction extent and a
99.50% order-sensitive score. All 61 aligned references resolve. Expressing
the first visible-line selection as an explicit ternary minimum, with the log
node declared between the bound and selection, reproduces the native `EBP`
visible-line count, `EBX` text-Y/vtable role, and complete instruction order.
The only remaining delta is two equivalent opcode spellings: native uses
`add eax, -2` while VC6 emits `sub eax, 2` for each source-level
`height / 16 - 2` bound.

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

## Recovery classification audit

The live Binary Ninja body accounts for every draw, traversal, font-mode,
scroll, caret, and batch-state path. The candidate has the same 400
instructions as native and `61/0/0` audited references. `--regions` isolates
the two differences to the equivalent `add eax, -2` versus `sub eax, 2`
spellings, so recovery is classified `semantic-complete` with a `compiler`
residual.
