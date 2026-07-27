# `quest_build_the_fortress`

Native target: `crimsonland.exe` at `0x004352d0` (429 bytes).

Live Binary Ninja evidence recovers 42 output entries. Entry zero is a
template-`0x40` spider wave at x `-50`, y
`float(terrain_texture_height) * 0.5`, trigger 100, count 6. Seven
template-`0x09` spawners follow at x 768; their y seed starts at `0x200`, the
position is `seed * 0.125 + 256`, triggers run from 1100 through 4700 in 600
steps, and count is 1.

The native body then writes `(128, 512)`, template `0x0e`, trigger 6500,
count 1 to entry 8. This is an original-code dead write: the nested grid starts
with `entry_count == 8` and overwrites that same slot on its first accepted
row. Six x seeds from `0x180` through `0x900` and rows 1 through 6 produce the
real template-`0x0a` grid. Row 1 is skipped only for x seeds `0x480` and
`0x600`. Each column starts its trigger at `entry_count * 600 + 0x157c`; each
accepted entry advances both trigger and count by 600 and 1 respectively.

The x87 evidence also corrected the ports. These coordinates are stored as
float, not truncated integers. Python now rounds at the native float-store
boundary, and Zig uses a wider intermediate before its final f32 cast. This
restores y values 448/384/320/256 and preserves the native fractional
`191.999984741` and `127.999984741` rows. The opening half-height likewise
preserves `.5` for odd terrain heights. The refreshed quest snapshot is
therefore evidence-backed rather than a replay fakematch.

The candidate reproduces the exact 102-instruction body and all eight audited
references, scoring 96.08% with a 21-instruction prefix. Moving `y_seed` to
its evidenced initialization point, keeping `entry_count` live before the
first loop, writing grid metadata directly, and incrementing trigger before
entry count account for the strong shape. Residuals are four unconstrained
placements of the independent entry-count/x-seed initializations and final
grid count/trigger increments. Explicit cursor and post-increment pointer
forms regress the register allocation and were rejected.

All six natural declaration orders for `spawn_index`, `trigger_time_ms`, and
`entry_count` were also compiled. They are fuzzy-byte neutral at 96.08%;
putting either count or index first shortens the exact prefix from 21 to 20,
while both trigger-first variants reproduce the retained result. The residual
initialization swaps therefore cannot be resolved by ordinary scalar source
order.

## Recorded grid-schedule search

`grid-schedule-mutations.json` exhaustively evaluated 63 single and pair
combinations over the dead entry-8 write and accepted-grid cursor schedule.
None improved the 96.08% baseline. Named dead-entry storage is byte-neutral;
split aggregate writes and early cursor advances regress instruction shape or
allocation. The complete result is in `experiments.jsonl` (spec
`63d5f1783fd858a39d11c9957d71b604dc60587e36256ec7f915e2922dc09ed8`).
