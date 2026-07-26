# `quest_build_syntax_terror`

Native target: `crimsonland.exe` at `0x00436c10` (339 bytes).

Live Binary Ninja evidence recovers four deterministic batches of template
`0x07` DenAlienBasic spawners. Each batch contains `player_count + 9` entries,
or four additional entries in hardcore mode; the native temporarily adds four
to the global player count and restores it before returning. Batch triggers
start at 1500 ms and advance by 30000 ms, while each entry advances by 300 ms.
The outer seed begins at `0x14c9` and advances by `0x35`; the inner seed begins
at `0x4c5` and advances by `0x15`. Both coordinates are cubic integer
polynomials reduced with signed `% 0x380`, then biased by 64 and converted to
float. Every entry has count one, so the final count is four times the active
inner-loop count. The Python and Zig ports agree with the recovered formulas.

The candidate preserves the native temporary hardcore mutation, nested loop
bounds, seed and trigger recurrences, signed division, x87 conversions,
24-byte entry layout, template/count metadata, and exact `0x1c` local frame.
The msvc6.5pp `/O2 /GB` backend compiles to 107 instructions versus the native
104 and scores 54.03%, improving the default msvc6.5 profile by 15.27
fuzzy-weighted bytes (49.52% to 54.03%) while increasing audited reference
agreement from 1/0/0 to 4/0/0.

The shared 24-byte `quest_spawn_entry_t` is now a flat semantic record:
`pos_x`, `pos_y`, `heading`, `template_id`, `trigger_time_ms`, and `count`.
Binary Ninja consequently renders those fields directly throughout the quest
builder cluster instead of routing ordinary accesses through nested
`pos_y_block.heading_block` paths. The separate trigger/count cursor types
remain available for the two loops that genuinely walk interior fields.

The residual is VC6 allocation and scheduling. Native keeps the output count
in EBP and inner seed in EBX, computes both coordinates before storing spawn
metadata, and restores the count through EBP. The candidate spills the count,
assigns the induction values differently, and schedules the independent
metadata stores before the coordinate arithmetic. Direct fields, one and two
coordinate temporaries, pointer/count and cursor builders, post-incremented
reservation, vector aggregate and all-fields setters were checked. A complete
6.5/6.5pp/7.0 optimizer matrix found msvc6.5pp `/O2 /GB` to be the strongest
profile. This remains an honest WIP without volatile state, dummy dependencies,
or forced-register constructs.

The scratch is classified `semantic-complete` with a `compiler` residual.
Fresh live disassembly confirms the exact `0x1c` frame, four outer batches,
signed cubic/modulo coordinate arithmetic, per-entry metadata, hardcore
player-count restoration, and both output-count return paths. The remaining
107/104 instruction delta is register assignment and scheduling; all four
audited references are matched.
