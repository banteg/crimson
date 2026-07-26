# `quest_build_target_practice`

Native target: `crimsonland.exe` at `0x00437a00` (240 bytes).

Live Binary Ninja evidence recovers 30 randomized targets. Each angle is
`(crt_rand() % 612) * 0.01`; each radius is `(crt_rand() % 8 + 2) * 32`.
Targets use template `0x36`, count 1, and a center of `(512, 512)`. Trigger
time starts at 2000 ms. Its step starts at 2000 ms, falls by 50 each entry,
and contributes at least 1100 ms until the reduced step reaches 500.

The source constructs a rounded radial-offset vector and a translated position
vector, then computes heading through vector subtraction and `angle()`, minus
half pi. That reproduces the native signed remainder lowering, 20-byte frame,
x87 position sequence, and exact `fxch`/`fpatan` heading sequence. The candidate
has the same 69 instructions and scores 89.86%. Residuals are the early
scheduling of three independent entry metadata stores, cursor advancement, and
one trigger-step register move. They remain unconstrained.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.
