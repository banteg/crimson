# `quest_build_spider_spawns`

Native target: `crimsonland.exe` at `0x00436d70` (365 bytes).

Live Binary Ninja evidence recovers eleven fixed entries. Four template `0x10`
fast alien spawners occupy `(128,128)`, `(896,896)`, `(896,128)`, and
`(128,896)` at 1500 ms/count one. Template `0x38` timer spiders spawn at
`(-64,512)` at 3000 ms and `(1088,512)` at 21000 ms, both count two. A
template `0x0a` slow spawner occupies `(512,512)` at 18000 ms. The remaining
template `0x10` entries are `(448,448)` at 20500 ms, `(576,448)` at 26000 ms,
`(576,576)` at 31500 ms, and `(448,576)` at 22000 ms, all count one. The
Python and Zig ports agree with the native ordering and constants.

Direct two-float position fields plus the metadata setter reproduce the
native shared registers for 128, 896, 512, 448, 576, template `0x10`, trigger
1500, and count one. The candidate has the same 73 instructions, no external
references, the exact 24-byte record offsets, all eleven entries, and the
constant output count. It scores 87.67%.

The residual consists only of independent VC6 scheduling. Native interleaves
the callee-saved pushes and later constant-register replacements with adjacent
record stores; the candidate groups the pushes and initializes each shared
constant slightly earlier. A two-float constructor introduces a disproven
eight-byte temporary and expands the function to 116 instructions, while a
five-argument scalar setter emits the same best code. `msvc6.5pp` is identical;
`msvc7.0` and `/G6` regress. The exact-length default-profile WIP is kept
without artificial dependencies or forced-register constructs.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.

## Direct metadata-store audit

`direct-metadata-site-mutations.json` independently replaces each of the
eleven metadata-setter calls with the equivalent direct template, trigger, and
count stores. Ten variants are byte-for-byte neutral. Expanding entry two
alone loses 10 fuzzy-weighted bytes. The fixed table values, offsets, and
setter semantics are therefore not hiding the remaining schedule difference;
the complete 11-variant record is retained in `experiments.jsonl`, and no
source mutation is kept.

## 2026-08-08 staged-constant pass

The native opening introduces the shared 128 coordinate, template, trigger,
count, and 896 coordinate at successive semantic publication points rather
than hoisting all five before the table stores. Staging those values as named
locals and directly publishing the first four repeated entries raises the
score from 87.67% to 89.04% and extends the prefix from two to six
instructions, with 73/73 instructions and 0/0/0 references preserved.

The remaining opening residual comes from VC6 grouping the two later 128
stores before reusing that register for 512. The only other differences are
the early loads of the shared 448 and 576 coordinates. Cursor and scalar
position-helper variants regress, so the stronger staged-constant form is
retained without barriers or forced registers.
