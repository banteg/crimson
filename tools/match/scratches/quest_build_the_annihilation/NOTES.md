# `quest_build_the_annihilation`

Native target: `crimsonland.exe` at `0x004382c0` (278 bytes).

Live Binary Ninja evidence recovers one template `0x2b` alien at `(128,
terrain_width / 2)`, trigger 500 ms, count two. Two twelve-entry template
`0x07` columns follow. Both use y positions 128 through 832 in steps of 64.
The first alternates x 832/896, triggers 500 through 6000 in 500 ms steps;
the second alternates x 896/832, triggers 45000 through 48300 in 300 ms
steps. All column entries have count one, and the final count is 25.

The retained source exactly reproduces all 278 native bytes and all 77
instructions, including the signed division by twelve, parity branches, loop
limits, store schedule, 24-byte stride, output count, and terrain-width
reference. Its normalized prefix is the full 77 instructions.

The missing source shape was a separate append count and parity index.
`entry_count` selects each output record while `index` controls alternating x
positions. VC6 strength-reduces the append count into the native
`template_id`-anchored induction pointer, so the position stores naturally use
negative offsets and the pointer advances before the parity index. This
recovers the native shape without declaring a negative-field cursor.

Binary Ninja gives those two evidenced native induction values a
layout-equivalent `quest_spawn_entry_template_cursor_t` presentation type.
Each cursor exposes the current `template_id`, `trigger_time_ms`, and `count`,
plus the next entry's position block, while retaining the actual 0x18-byte
stride. The exact compiler-facing source confirms that this is the optimized
form of the append count, not a source-level negative pointer.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, constants,
record stores, induction policy, and output count. The candidate is an exact
normalized instruction and reference match, so no recovery or compiler
residual remains.

## 2026-07-27 focused family pass

Live Binary Ninja reconfirmed the opening alien, both twelve-entry columns,
their alternating x positions, and final count 25. MSVC 6.0, 6.5, 6.5
Processor Pack, and 6.6 tie at 74.02597402597402%; 7.0 regresses to
65.80645161290323%. `/GB`, `/G5`, `/G7`, `/Ox`, and `/Ob1` tie, while
`/G6` falls to 66.23376623376623%.

`loop-cursor-lifetime-mutations.json` (SHA-256
`5ef198bf3c13aadf3ddc1ad0b48ccdc5d40da36443b11a0ae994459fd8d8ef53`)
recorded four variants. Moving the second cursor declaration is byte-neutral;
preadvance/negative-index spellings regress by 3.61 and 79.43 weighted bytes,
confirming that the native negative offsets are optimizer presentation rather
than source evidence. `loop-metadata-mutations.json` (SHA-256
`002887e33f8dc81787443d2d6de12b5de45404c4ddcf1605af2e46c7fa21b83d`)
recorded both direct-field singles and their pair; all are byte-neutral.
No source change is retained. Validation remains 205.7922077922078/278
weighted bytes, a 72.20779220779221 gap, 77/77 instructions, prefix fifteen,
and references 1/0/0.

The `quest_build_the_unblitzkrieg` two-argument metadata helper was also
replayed across both running columns. Moving `count = 1` after the helper is
byte-for-byte neutral at 74.03%, 77/77 instructions, prefix fifteen, and
`1/0/0` references. This confirms that its improvement is tied to
Unblitzkrieg's longer metadata schedule rather than a missing shared helper ABI
in every looped quest builder.

## 2026-08-08 exact recovery

The initial-entry lifetime sweep evaluated 29 variants without improving the
74.03% persistent-cursor baseline. Replacing each persistent cursor with an
index-relative local then raised the candidate to 90.91% and naturally selected
the native `template_id` induction base. Five helper-store permutations and 35
cursor-expression variants were neutral or worse at that intermediate score.

`append-count-recovery-mutations.json` (SHA-256
`c0f576c08f4a29dd3a3b1243da4bf7683f24ee9547056d3867fc46502198ce0b`)
then tested the shared append-count hypothesis from the original 74.03%
baseline. The complete three-site variant is exact and improves the weighted
score by 72.20779220779221 bytes; partial variants fail to compile because the
shared `entry_count` definition and both consumers are intentionally one
atomic source model. The retained source SHA-256 is
`be8329a98fa0344d7b10f1e8866134ffcecf8650d935fc11b19f5c94156e7926`.
The experiment ledger records 83 unique variants, one exact winner, no
tradeoffs, and no repeated variants.
