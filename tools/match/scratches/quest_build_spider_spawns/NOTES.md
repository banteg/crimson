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
