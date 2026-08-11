# `quest_build_the_gang_wars`

Native target: `crimsonland.exe` at `0x00435120` (424 bytes).

Live Binary Ninja evidence recovers 24 entries. Two opening template-`0x12`
ring formations spawn at x `-150` and `1174`, y
`float(terrain_texture_height) * 0.5`, triggers 100 and 2500, and count 1.
Ten more right-side rings start at trigger 5500, advance by 4000, and use
count 2. Entry 12 is a template-`0x13` chain at the native fixed coordinate
`(512, 1152)`, trigger 50500, count 1. Ten left-side rings run from trigger
59500 through 95500 with the same 4000 step and count 2. Entry 23 is another
fixed `(512, 1152)` chain at trigger 107500, count 3.

The evidence also corrected two port assumptions. The chain coordinates are
not derived from the arena size, and the side-wave y value preserves a
fractional half-height rather than using integer floor division. Python and
Zig now share an explicitly exact-position append path for this proven
exception to the usual native quest-coordinate truncation.

The candidate reproduces the exact 92-instruction body and all eight audited
references, scoring 98.91%. A continuous append index publishes the two
opening records. Their metadata is written directly, with a shared count-one
lifetime carried across the boundary. This recovers the complete prologue and
opening table through instruction 33. The integer index is then strength-
reduced into the same native loop pointer anchors and remains substantially
stronger than an explicit cursor. One-field trigger publication on both fixed
chain entries recovers the complete middle and tail schedules. The sole
residual is an independent swap between the first loop cursor anchor and its
initial trigger load. VC6.5pp and VC6.6 produce the same result as the default
profile, so no override is justified.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.

## Exact-tail follow-up (2026-07-27)

The five-compiler and six-flag matrices retain VC6 `/O2 /GB`; VC7 and `/G6`
regress, while `/G5`, `/G7`, `/Ox`, and `/Ob1` tie. The first recorded
25-variant sweep finds an additive `4.608695652173878` weighted-byte gain for
each repeated loop setter; retaining both raises weighted bytes from
`368.69565217391306` to `377.9130434782609` and reduces the gap from
`55.30434782608694` to `46.086956521739125`. A 12-variant retained-source
follow-up and five helper-store permutations find no further gain. The final
candidate at that checkpoint remained 92/92 instructions with a four-
instruction prefix and `7/0/0` references.

## Append-prefix recovery (2026-08-08)

Publishing the two opening records through the loop's append index, spelling
their metadata directly, and sharing the count-one value improves the score
from 89.13% to 94.57%. It extends the exact prefix from four to 33 instructions
while preserving 92/92 instructions and resolving `8/0/0` references.
Replaying explicit record and trigger-field cursors against this stronger
prefix regresses the already correct loop, while direct later metadata and
staged left-wave position variants are byte-neutral. Only the opening
publication shape is retained.

## Fixed-chain trigger boundary recovery (2026-08-08)

Splitting each fixed chain's metadata into a direct template store, an inlined
one-field trigger setter, and a direct count store recovers two independent
native schedules. At entry 12, VC6 now publishes template and trigger before
constructing the left-wave x component. At entry 23, the same boundary lets
the epilogue pops interleave between the final metadata stores exactly as in
the target. The score rises from 94.57% to 98.91% with the exact 92/92
instructions and references `8/0/0`. Applying the setter inside the repeated
right loop is byte-neutral and is not retained.

## First-wave loop-form replay (2026-08-12)

Live native comparison still isolates the five-byte residual to one independent
swap after the second opening record: native materializes the first loop's
cursor anchor before loading trigger 5500, while the candidate loads the
trigger first. `current-first-wave-loop-form-mutations.json` (SHA-256
`adc370d6edf1d58158e6f96a54fd0d320017dd1d2a3251327ec33e37564fa6c8`)
replays six exact `do`, `while`, and `for` forms on the current source,
including both update-clause orders and explicit versus conditional
decrements.

All six variants compile byte-for-byte identically to the **98.913043%**
baseline. Together with the existing pointer, reference, declaration-order,
and constructor sweeps, this bounds the remaining cursor/trigger order as VC6
scheduling rather than a missing high-level loop form. The canonical source
remains 92/92 instructions, a 33-instruction prefix, and clean `8/0/0`
references; its SHA-256 is
`12657dca669e42ee8bb824442c012e8599ab6aa5165fdfa3d1531c2c782b25ac`.
