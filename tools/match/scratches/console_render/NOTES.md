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

## Recorded visible-line sweeps

`visible-line-adjustment-mutations.json` and
`visible-line-staged-mutations.json` evaluated 16 signed-local, reused-local,
and staged-minimum shapes. Every compile-valid alternative was byte-neutral
or worse, so no source change was retained. The complete records reinforce
that the final two differences are compiler spelling rather than missing
visible-line behavior.

## Exact-tail audit (2026-07-27)

A fresh live Binary Ninja read and focused `--regions` comparison reconfirm the
two isolated `add eax, -2` versus `sub eax, 2` spellings. The supported
MSVC 6.0, 6.5, and 6.6 compilers are byte-identical at the baseline; the
Processor Pack profile regresses to 87.30%, and VC7 does not compile this
source. `/Ox`, `/G5`, and `/Ob1` are byte-neutral, while `/G6`, `/Oy-`, `/O1`,
and `/Os` regress.

`visible-line-decrement-mutations.json` adds 24 bounded single- and paired-site
tests for compound subtraction, pre/post decrement pairs, and negative-left
addition. All 24 variants are byte-identical to the **99.50%**, 400/400,
`61/0/0` baseline. A recorded `two-pre-decrements-confirmation` probe is also
exactly neutral. No source rewrite was retained; baseline and final metrics are
unchanged.

`unsigned-line-adjustment-mutations.json` closes the remaining unsigned
constant spelling family. Its 15 complete single/paired variants cover
`0xfffffffeu`, `~1u`, and a cast negative at both native sites; every variant
is byte-identical to baseline. The recorded spec SHA is
`54aab9197fcba724952722ce74ecda8a21b6044afc530a765e8f73d74263df72`.
This leaves no evidenced C/C++ arithmetic spelling that selects native
`add eax, -2`; the canonical source remains unchanged.
