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

The append count publishes entry zero and the seven-entry opening walk,
identifies the dead entry-8 write without advancing past it, drives the
overwritten grid, and supplies the output count. Direct dead-entry metadata
places the x-seed initialization at the native boundary. The grid then uses a
trigger-field cursor, a temporary record view for position, and a distinct
template-field owner. Advancing the logical count after position construction
but before metadata publication reproduces its native x87-gap placement. The
result matches all 102 instructions and all eight audited references exactly.

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

`first-loop-boundary-mutations.json` adds five typed record/position cursor
forms for the seven-entry opening loop. Only the position pointer is
byte-neutral; the record-cursor shapes lose 42.1 to 50.5 fuzzy-weighted bytes.
`vector-helper-mutations.json` adds six constructor/assignment shapes: three
constructor spellings are neutral and all explicit assignment operators
regress. Their SHA-256 values are
`51cde434112e54eed7509df5563a01482763423d1ff0ad31499d59f9fca3168c`
and
`3345a931147cba67328d3a8fa60d9ada42e5b5669cba0e3c77ce624535bf1f30`.
MSVC 6.0/6.5/6.6 tie, Processor Pack and MSVC 7.0 regress, and `/G5`, `/G7`,
`/Ox`, and `/Ob1` are neutral while `/G6` regresses.

## 2026-08-08 append-count recovery

Replacing the separate opening index and preseeded count with continuous
publication improves the candidate from 96.08% to 98.04%, extends the exact
prefix from 21 to 70 instructions, and preserves 102/102 instructions and
references 8/0/0. Moving the x-seed declaration after the direct dead-entry
metadata stores makes the entire 70-instruction opening exact. The remaining
8.4117647058824 weighted-byte gap consists only of the two independent grid
increment placements. The retained source SHA-256 is
`f7590cfaa68ff55aa016c85818519de6ca2154c3e7a161e142205b6a08d607dd`.

## 2026-08-08 field-cursor exact recovery

The native grid keeps a trigger-field-biased cursor across each column. Each
accepted row constructs position through a record view, advances the logical
append count, publishes template through its own field pointer, then publishes
trigger and count through the trigger cursor before advancing it by six words.
This source shape resolves both residual increment placements and the final
template/trigger scheduling swap without dependencies or layout changes.
Retained source SHA-256:
`0719dece3767726effe140acd07a8810c69d96a0bcadab6063aae63979d3f219`.
