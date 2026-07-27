# `ui_cursor_render`

Native target: `crimsonland.exe` at `0x0041a040` (730 bytes).

Current natural VC6 reconstruction is 177/177 instructions with a 98.87%
order-sensitive score, masked references `57/0/0`, and full semantics. The
only normalized difference is instruction scheduling around the final cursor
quad: the native computes its Y
coordinate before pushing both size arguments, while VC6 currently hoists one
constant push and the vtable load.

Live Binary Ninja shows two ordinary batches. The first draws four atlas
particles around the mouse with a sine-squared alpha pulse. The second draws
the 32 by 32 cursor texture itself. The shared animation timers advance from
the frame delta before either batch.

IDA had incorrectly marked this game-specific routine as a library function.
The name-map overlay opts it back into the native manifest based on its game
globals, effect-atlas call, and nine game call sites.

The map also records VC6's `__CIpow` relocation spelling as an alias of the
native `crt_ci_pow` helper at `0x00461140`; the aligned call is now fully
resolved rather than merely normalized.

No inline assembly, volatile state, dummy references, or dead expressions are
used.

## Recovery classification audit

A fresh focused `--regions` run is unchanged before and after classification:
**98.87%**, 177/177 instructions, prefix 158, and `57/0/0` references. The
single region at native `0x0041a2c2..0x0041a2ff` contains the same final
32-by-32 draw call and coordinate arithmetic, differing only in one constant
push and vtable-load schedule. Both batches, timers, texture state, four pulse
quads, and final cursor quad are accounted for.

The full compiler/flag sweep found no exact profile flip, with stock VC6.5
`/O2 /GB` remaining best. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.

`final-quad-coordinate-mutations.json` evaluated three named, staged, and
component-wise coordinate lifetimes for the closing draw. All three compile
byte-identically, so no cosmetic source rewrite was retained.
