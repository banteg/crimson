# `quest_build_lizard_zombie_pact`

Native target: `crimsonland.exe` at `0x00438700` (311 bytes).

Live Binary Ninja evidence recovers sixteen paired template `0x41` zombie
waves from the right and left edge midpoints. Triggers begin at 1500 ms,
advance by 7000 ms, and stop before 113500 ms; each edge entry has count six.
On waves 0, 5, 10, and 15, the quest also adds two template `0x0c` alien
spawners at x 356. Their y coordinates are `wave / 5 * 180 + 256` and
`wave / 5 * 180 + 384`, with counts `wave / 5 + 1` and `wave / 5 + 2`.
The final count is 40.

The retained source preserves the native pointer-plus-count builder, signed
width halving, x87 integer-to-float conversions, 24-byte entry stride, signed
division for the five-wave predicate, separately lowered quotient for the
spawner group, loop arithmetic, and output count. Under the default VC6 profile
it matches all 311 bytes and all 95 instructions, with all three constant
references resolved.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, constant,
record-store, and output-count policy. The candidate is byte-exact, so no
recovery or residual classification is needed.

## 2026-07-27 focused profile and mutation pass

MSVC 6.0, 6.5, and 6.6 tied at 56.84210526315789%; both the 6.5 Processor
Pack and MSVC 7.0 regressed to 43.24%. `/GB`, `/G5`, `/G7`, `/Ox`, and
`/Ob1` tied, while `/G6` regressed.

`local-declaration-order-mutations.json` (SHA-256
`7bcdd17056bc032b017c333b71f20bc1ebf1ad6f3dda5b97206675cbbbf5db79`)
recorded five complete variants. Three local-order spellings produced the
same winning bytes; the then-retained wave-trigger-builder order was the
smallest source-only representation of the native wave and trigger lifetimes.
No behavior, entry layout, or arithmetic changed.

Fresh scratch recomputation improved 176.77894736842106/311 to
180.05263157894737/311 weighted bytes: 56.84210526315789% to
57.89473684210527%, with the gap falling from 134.22105263157894 to
130.94736842105263. The validated result remains exactly 95/95 instructions,
prefix two, and references 3/0/0.

## Builder-base lifetime audit

Native keeps the entry base in EBP, wave in EDI, and trigger in EBX.
`builder-base-lifetime-mutations.json` (SHA-256
`16ace3b5300f91a6ebede167dafe9f88deaace8b5f4d7c814b020d92782edbf4`)
tested five placements for an explicit semantic base alias around the retained
wave/trigger order. Four were byte-neutral and constructing the builder before
the induction locals lost 3.274 weighted bytes. The alias is fully folded by
VC6 and does not break the remaining allocation cycle, so no source change is
retained.

## 2026-07-30 exact recovery

A fresh boundary-first pass replaced the apparent global register-allocation
cycle with a sequence of local source-shape constraints:

- Direct indexing with count updates after metadata on the two edge records
  and two spawner records added 22.916 weighted bytes, moving the candidate
  from 57.895% to 65.263%.
- Preserving the upper spawner pointer and index before lowering `wave / 5`
  added 88.389 weighted bytes and moved the candidate to 93.684%.
- Re-evaluating declaration order after those source changes selected
  builder-wave-trigger and moved the candidate to 96.842%.
- Giving the upper count store its own typed pointer boundary moved the
  candidate to 97.895%.
- Reusing the exact two-field metadata helper idiom from
  `quest_build_nesting_grounds`, followed by the separate count store, closed
  the final 6.547 weighted bytes.

The final source matches 311/311 bytes and 95/95 instructions, has a 95
instruction prefix, and resolves references 3/0/0. Nine recorded experiment
entries cover 119 evaluated variants and one exact winner. Exact source
SHA-256: `42f349ea57e7cf57763212f80aae65746bd265f58b0dd7be7c8f3dd36549248d`.
Experiment ledger SHA-256:
`2a020d1eb210585a6059cbdce12cb858ff2ca464bafc5e41b1eeaaef74365cdf`.

The exact-neighbor TU probe was byte-neutral. Raw storage and alternate loop
forms regressed or were neutral, bounding those hypotheses without retaining
artificial dependencies or forced-register constructs.
