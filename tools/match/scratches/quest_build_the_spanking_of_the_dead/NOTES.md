# `quest_build_the_spanking_of_the_dead`

Native target: `crimsonland.exe` at `0x004358a0` (391 bytes).

Live Binary Ninja evidence recovers 132 spawn entries. Two opening bonus aliens
use template `0x27`, trigger 500, count 1, at `(256, 512)` and `(768, 512)`.
The next 128 entries form a shrinking zombie spiral. Trigger time starts at
5000 and advances by 300 while it is below 43400. For zero-based step `i`, the
native x87 sequence computes angle `i * 0.333333343`, radius
`512 - i * 3.79999995`, and position `(cos(angle) * radius + 512,
sin(angle) * radius + 512)`. Each spiral entry uses heading `angle`, template
`0x41`, and count 1. The two final template-`0x42` waves are fixed at
`(1280, 512)` and `(-256, 512)`, with count 16 and triggers `i * 300 + 10000`
and `i * 300 + 20000`.

The candidate reproduces the exact 94-instruction length, all five audited
references, the loop bounds, x87 trigonometric sequence, final indices, and
trigger arithmetic. It scores 60.64%. Residuals are unconstrained VC6
scheduling: the candidate hoists independent loop metadata stores and trigger
updates ahead of the trigonometry, and schedules parts of the opening/final
fixed entries differently. Raw indexed access kept the metadata after the
math, but regressed the register allocation and score to 57.45%; a local spawn
pointer is the strongest plausible source shape. VC6.5pp and VC6.6 reproduce
the default result, while VC7 regresses sharply, so no compiler override is
warranted.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.

## 2026-07-27 focused profile and mutation pass

MSVC 6.0, 6.5, 6.5 Processor Pack, and 6.6 tied at
60.63829787234043%; MSVC 7.0 regressed to 31.91%. `/GB`, `/G5`, `/G7`,
`/Ox`, and `/Ob1` tied, while `/G6` regressed.

`fixed-position-store-mutations.json` (SHA-256
`f4160d3b2795d44e249c77a690b5f138929f4852eb219fe082438d6b02b7c74b`)
recorded three complete variants. The retained tail variant uses direct x/y
stores for the two fixed waves, matching the native scalar-store shape without
changing either entry. Applying the same form to the opening pair, alone or
with the tail, regressed and was rejected.

Fresh scratch recomputation improved 237.09574468085108/391 to
246.26519337016572/391 weighted bytes: 60.63829787234043% to
62.98342541436464%, with the gap falling from 153.90425531914892 to
144.73480662983428. The validated result has 87/94 instructions, prefix four,
and preserves references 5/0/0.
