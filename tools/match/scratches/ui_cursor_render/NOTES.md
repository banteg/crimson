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

`final-quad-receiver-lifetime-mutations.json` extends that audit with five
local pointer/reference receivers, named sizes, and coordinate declaration
orders. Every alternative is again byte-identical at 177 instructions,
98.87%, and `57/0/0` references. The final size-push/vtable-load swap is an
optimizer scheduling boundary rather than a missing receiver lifetime.

## Exact-tail audit (2026-07-27)

A new live Binary Ninja check keeps the only residual at the final 32-by-32
quad. MSVC 6.0, 6.5, and 6.6 are byte-identical; Processor Pack regresses to
75.29% with two reference mismatches, and VC7 does not compile this source.
No tested flag profile is exact.

`final-quad-staged-scalar-mutations.json` evaluates four compound-scalar and
array forms: the three scalar forms are byte-neutral, while the array form
falls to 93.26% and introduces one reference mismatch.
`final-quad-vector-mutations.json` evaluates three vector-type/materialization
combinations: adding the unused type is neutral, but materializing the vector
has the same 93.26% regression. The recorded `compound-final-y-confirmation`
probe is neutral. No source change was retained; final remains **98.87%**,
177/177, prefix 158, `57/0/0`.

`final-quad-inline-helper-mutations.json` adds complete two-site coverage for
four inline/force-inline draw helpers and the closing quad call. All four
complete helper uses are byte-identical at 98.87%, 177/177, prefix 158, and
`57/0/0`. Live native code computes Y before both size pushes, whereas VC6
continues to inline the helpers into the same constant-push/vtable-load
schedule. The helper boundary is therefore another recorded compiler-only
negative.
