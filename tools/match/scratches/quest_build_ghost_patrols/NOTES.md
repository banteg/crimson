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
constant output count, and all five references. It compiles to the same 90
instructions, preserves a 36-instruction prefix, and scores 86.67%.

The residual is independent VC6 scheduling. Native advances the induction
pointer and wave before the midpoint conversion completes, then stores the
loop metadata through negative offsets; the candidate schedules those stores
before the x87 result. The tail count-one stores and epilogue arithmetic are
likewise reordered. A direct cursor, a post-incremented cursor, ternary float
selection, direct metadata fields, and explicit count-one lifetime were
checked. `msvc6.5pp` and `msvc6.6` are identical; `msvc7.0` regresses to 85
instructions. This remains an honest WIP without volatile or dependency-only
scheduler steering.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.

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
