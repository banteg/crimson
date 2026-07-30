# `quest_build_the_annihilation`

Native target: `crimsonland.exe` at `0x004382c0` (278 bytes).

Live Binary Ninja evidence recovers one template `0x2b` alien at `(128,
terrain_width / 2)`, trigger 500 ms, count two. Two twelve-entry template
`0x07` columns follow. Both use y positions 128 through 832 in steps of 64.
The first alternates x 832/896, triggers 500 through 6000 in 500 ms steps;
the second alternates x 896/832, triggers 45000 through 48300 in 300 ms
steps. All column entries have count one, and the final count is 25.

The candidate reproduces the native registers, signed division by twelve,
parity branches, loop limits, update order, 24-byte stride, and output count.
Placing the loop locals after the initial position assignment preserves the
native 15-instruction prefix. The candidate has the same 77 instructions and
resolves the terrain-width reference.

The residual is induction-base selection and independent-store scheduling.
The native anchors both loops at `template_id` and addresses position through
negative offsets; VC6 anchors the equivalent source at the record start. A
metadata-only setter emits the same best result, while moving the loop-local
lifetimes earlier degrades register initialization. `msvc6.5pp` is identical.
The 74.03% candidate remains an honest WIP rather than encoding the optimizer's
negative-field cursor into the source.

Binary Ninja now gives those two evidenced native induction values a
layout-equivalent `quest_spawn_entry_template_cursor_t` presentation type.
Each cursor exposes the current `template_id`, `trigger_time_ms`, and `count`,
plus the next entry's position block, while retaining the actual 0x18-byte
stride. This recovers the optimized loop shape without pretending that the
compiler-facing source declared a negative-field cursor.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.

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
