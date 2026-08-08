# `quest_build_ghost_patrols`

Native target: `crimsonland.exe` at `0x00436200` (334 bytes).

Live Binary Ninja evidence recovers one opening template `0x2b` red alien at
the right edge, trigger 1500 and count two. Twelve template `0x19` ring patrols
then alternate x between -128 and 1152 at the vertical midpoint, beginning at
2500 ms and advancing by 2500 ms with count one. The tail adds a template
`0x2b` entry at `(-264, midpoint)` and trigger `(wave - 1) * 2500`, followed by
a template `0x18` entry at `(-128, midpoint)` and trigger
`(wave * 5 + 15) * 500`. The final count is 15. The Python and Zig ports agree
for the native 1024-square quest terrain.

The retained append-count source form reproduces the native biased ESI
induction pointer, signed `% 2` lowering, alternating immediate stores, signed
width halving, x87 conversions, loop variables, tail multiplication chains,
constant output count, and all five references. It matches all 90 native
instructions exactly.

The decisive house-style boundary is separate indexed publication: position
and metadata both use `spawns[entry_count]` expressions rather than sharing a
record pointer. VC6 strength-reduces those repeated expressions into the native
biased induction pointer, advances it before the midpoint conversion finishes,
and publishes metadata through negative offsets. Direct metadata on the two
tail entries likewise preserves their native arithmetic and epilogue schedule.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, constants,
record stores, induction policy, and output count. The candidate is an exact
normalized instruction and reference match, so no recovery or compiler
residual remains.

## Exact-tail follow-up (2026-07-27)

The five-compiler and six-flag matrices confirm the existing VC6 `/O2 /GB`
profile: the ordinary VC6 variants tie, VC7 regresses, and `/G6` is the only
tested VC6 flag spelling that worsens the result. Recorded source-order and
helper-store sweeps evaluate 39 variants covering loop-local order, biased
pointer spellings, metadata fields, update order, both tail setters, and all
helper store permutations. None improves the `270.9111111111111/334`
weighted bytes, 90/90 instructions, 14-instruction prefix, or `5/0/0`
references, so that pass retained the then-current source.

## 2026-08-08 append-count recovery

The Annihilation recovery suggested separating the output append count from
the wave counter. `append-count-recovery-mutations.json` (SHA-256
`d85107c4a35d387413eefdce1acd74ef744080d78e3edb57811f471417d14836`)
tested all seven combinations of the initial entry, ring loop, and tail using
that model. Three variants improve without tradeoffs. The initial-entry
lifetime is the code-generation trigger; adding the counted loop and tail is
byte-neutral and retains one coherent append cursor across all fifteen output
records.

The complete model raises the weighted score from 270.9111111111111/334
(81.11%) to 289.4666666666667/334 (86.67%), extends the exact prefix from 14
to 36 instructions, preserves 90/90 instructions and `5/0/0` references, and
moves the first mismatch from instruction 14 to instruction 36. The retained
source SHA-256 is
`161c996f3bb1cf2333b5a76eefb6789f55ab0dabe970deedb432280624c58c25`.
The experiment ledger now contains 46 unique variants across three distinct
sweeps with no repeated variants.

Natural follow-ups moved the append increment around the loop updates, used a
persistent record cursor, split the x store from the remaining record stores,
and introduced explicit tail-trigger locals. None exceeded 86.67%; split
cursors also changed register allocation and instruction count. The remaining
three regions are still honest VC6 scheduling residuals, so no negative-field
cursor or dependency-only steering is retained.

## 2026-08-08 exact indexed-publication recovery

Direct metadata for both tail entries first raises the post-append candidate
from 86.67% to 92.22%. Replacing the loop's shared record pointer with separate
`spawns[entry_count]` position and metadata expressions then recovers the exact
native induction schedule and produces a 100% match: 90/90 instructions and
references `5/0/0`. Retained source SHA-256:
`75d1df00a1ce362ab80271f3830c1f11671f1e3e628dff4987aedeb5b79839b4`.
