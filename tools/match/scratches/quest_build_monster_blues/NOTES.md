# `quest_build_monster_blues`

Native target: `crimsonland.exe` at `0x00434860` (348 bytes).

Live Binary Ninja evidence recovers four opening entries: a template `0x04`
lizard at `(-50, height / 2)` at 500 ms/count 10; a template `0x06` alien at
`(1074, height / 2)` at 7500 ms/count 10; and two template `0x03` spiders at
`(512, 1088)` and `(512, -64)` at 17500 ms/count 12. Sixty-four entries then
spawn at `(-64, 512)`, beginning at 27500 ms and advancing by 900 ms. Signed
`index % 4` selects template `0x06` for remainder zero, `0x03` for remainder
one, and `0x05` otherwise; the count is signed `index / 8 + 2`. The function
publishes 68 entries. The Python and Zig ports agree with the recovered table.

The reusable `quest_vec2_t` constructor reproduces the native eight-byte
position temporary and pair copies. Assigning the loop template directly in
each branch reproduces the native biased induction pointer, signed remainder
correction, branch stores, signed divide-by-eight lowering, trigger recurrence,
constant position registers, pointer stride, loop bound, and epilogue. That
64-entry loop matches exactly. Publishing the four fixed opening entries
through one count raises the full candidate to 92.63% with the same 95
instructions, a 22-instruction prefix, and three resolved references.

Binary Ninja now types the native loop's template-anchored induction value as
`quest_spawn_entry_template_cursor_t *`. The 0x18-byte view exposes the
current `template_id` and `trigger_time_ms` fields, keeps the record-sized
advance explicit, and leaves the compiler-facing source on the canonical
`quest_spawn_entry_t` array.

The residual is independent VC6 scheduling in the four fixed entries. Native
pushes long-lived loop registers between the first x87 conversion and metadata
stores, while the candidate completes more entry stores before those pushes;
the final fixed-entry trigger store also crosses loop initialization. Scalar
positions, a cursor loop, a local template selector, direct fixed metadata, a
whole-entry setter, `msvc6.5pp`, `msvc7.0`, and `/G6` were checked. They remove
the proven temporary, lose the exact loop lowering, or regress the score. This
remains an honest exact-length WIP without dependency-only scheduler steering.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.

## Exact-tail follow-up (2026-07-27)

The five-compiler and six-flag matrices retain VC6 `/O2 /GB`; VC7 and `/G6`
regress, while `/G5`, `/G7`, `/Ox`, and `/Ob1` are code-identical to the
baseline. Three recorded fixed-prefix sweeps evaluate 18 variants: moving the
loop locals ahead of the four fixed entries regresses, individual and paired
direct metadata spellings are at best neutral, and all helper store
permutations are neutral or worse. The exact repeated loop remains untouched,
and the source stays at `285.7263157894737/348` weighted bytes, 95/95
instructions, a nine-instruction prefix, and `2/0/0` references.

## 2026-08-08 append-prefix improvement

Replacing the four fixed opening indices with zero-based publication improves
the candidate from 82.11% to 92.63% and extends the exact prefix from nine to
22 instructions. The loop retains its original `index + 4` ownership, exact
lowering, and fixed output count, so the gain is isolated to the opening table.
The retained source SHA-256 is
`90d0455855d1626d12b05e43ebf2ac5c42114c44bdd34dc69fb1bd35541be315`.
