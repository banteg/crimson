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

The recovered source matches all **339/339 bytes** and **104/104 instructions**
under the evidenced `msvc6.5 /O2 /GB` profile, with all six audited references
resolved. It preserves the native temporary hardcore mutation, nested loop
bounds, seed and trigger recurrences, signed division, x87 conversions,
24-byte entry layout, template/count metadata, and exact `0x1c` local frame.

The shared 24-byte `quest_spawn_entry_t` is now a flat semantic record:
`pos_x`, `pos_y`, `heading`, `template_id`, `trigger_time_ms`, and `count`.
Binary Ninja consequently renders those fields directly throughout the quest
builder cluster instead of routing ordinary accesses through nested
`pos_y_block.heading_block` paths. The separate trigger/count cursor types
remain available for the two loops that genuinely walk interior fields.

Three source-level relationships recover the native allocation and schedule.
Naming the two outer-loop polynomial terms keeps their true loop-invariant
lifetimes visible to VC6, which assigns the emitted count to EBP and the inner
seed to EBX. Addressing `spawns[entry_count]` separately for the position and
metadata setters preserves the native order: both coordinates are completed
before template, trigger, and count are stored. Finally, incrementing the
independent outer index before advancing the outer seed selects the native
spill-slot assignment while VC6 still emits the seed increment first.

These are ordinary semantic source forms backed by the native dataflow. No
volatile state, dummy dependency, forced register, or artificial control flow
is used.

## 2026-07-27 focused profile and mutation pass

The initial compiler profile pass reproduced 49.523809523809526% under MSVC
6.0, 6.5, and 6.6. The 6.5 Processor Pack reached 54.0284% and four matched
references, but the product/build provenance noted above still excludes it;
MSVC 7.0 scored 37.91%. `/GB`, `/G5`, `/G7`, `/Ox`, and `/Ob1` tied, while
`/G6` regressed.

At the intermediate source, `local-declaration-order-mutations.json` (SHA-256
`55e5669524b23537f156632a6488f1bb0beecdbc2e05a80d876c0c6f06ae8214`)
recorded all 15 requested single and interaction variants. Reordering the
semantic outer-loop locals to trigger, index, seed recovered the native
induction-value lifetime shape. The alternate index-trigger-seed spelling was
byte-identical; entry base/count reorderings were neutral, so the smallest
winning order change was retained.

Fresh scratch recomputation improved 167.8857142857143/339 to
220.5933014354067/339 weighted bytes: 49.523809523809526% to
65.07177033492823%, with the gap falling from 171.1142857142857 to
118.40669856459331. The validated result has 105/104 instructions, prefix
two, and six matched references with no mismatch or unresolved reference.

## 2026-07-29 exact recovery

Naming `outer_x_term` and `outer_y_term` raised the intermediate result from
65.07% to 85.58%, removed the instruction-count delta, and extended the exact
prefix from two to twelve instructions. Selecting the index-trigger-seed
declaration order then reached 86.54% and a fifteen-instruction prefix.

The separate indexed position/metadata expressions recovered the native store
schedule and raised the score to 94.23%. At that point the only differences
were the stack slots assigned to `outer_index` and `outer_seed`.
`outer-update-order-mutations.json` exhaustively tested the five remaining
orders of the three independent loop updates. Advancing `outer_index` before
`outer_seed` selected the native slots and produced the exact 339-byte object.
The declaration, inner-lifetime, and split-declaration sweeps record the bounded
neutral and regressing alternatives.
