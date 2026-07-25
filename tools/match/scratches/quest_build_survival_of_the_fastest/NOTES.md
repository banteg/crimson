# `quest_build_survival_of_the_fastest`

Native target: `crimsonland.exe` at `0x00437060` (861 bytes).

Live Binary Ninja disassembly recovers a 26-entry route. Heading is left
untouched throughout and every entry has count one:

- entries 0-5 move east from (256,256) to (616,256) in 72-unit steps,
  using template `0x10` at triggers 500 through 5000 ms in 900 ms steps;
- entries 6-11 move south from (688,256) to (688,616), continuing triggers
  5900 through 10400 ms;
- entries 12-15 move west across y=688 from x=688 to x=472, at triggers
  11300 through 14000 ms;
- entries 16-19 move north along x=400 from y=688 to y=472, at triggers
  14900 through 17600 ms;
- entries 20-21 move east from (400,400) to (472,400), at triggers 18500
  and 19400 ms;
- entries 22-25 are fixed corners: template `0x10` at (128,128), template
  `0x07` at (896,128), template `0x07` at (128,896), and template `0x10` at
  (896,896). The top pair triggers at 22300 ms and the bottom pair at
  24300 ms.

The fixed final coordinates corrected the Zig port, which had scaled the four
corners by runtime terrain dimensions. The native builder has no terrain-size
references.

The candidate scores 62.02% with a five-instruction exact prefix, 217
candidate instructions against 228 native instructions, and no static-reference
debt. A small builder object plus pointer-based first phases preserves the
native generalized threshold loops at 16, 20, and 22 entries. Those middle
regions individually score between 75% and 91%, including the recovered
coordinate and trigger-time formulas.

The remaining mismatch is optimizer shape, not unresolved behavior. VC6
eliminates the first two phase counters and starts the shared entry/path
registers at twelve, while the candidate retains induction through the builder
count. The candidate also schedules independent template/count stores before
some x87 coordinate conversions, and folds more corner float literals directly
into stores. Fixed-count, combined-setter, and corner-vector-constructor
spellings all regressed materially; the latter changed the frame from 12 to 20
bytes. No volatile state, dummy dependencies, or register-forcing constructs
are used.

## Cursor type recovery

The native loops intentionally advance pointers rooted at each entry's
`trigger_time_ms` field, so their negative indices are genuine interior-cursor
accesses rather than missing `quest_spawn_entry_t` base types. The five
phase cursors are now saved as named `int32_t *` locals in Binary Ninja.

The final four fixed-corner pointers are different: each points to a complete
entry, but Binary Ninja had degraded all four to `int32_t *`. Address-keyed
local annotations recover them as `quest_spawn_entry_t *`, and live readback
now renders `pos_x`, `pos_y`, `template_id`, `trigger_time_ms`, and `count`
for every corner. This is presentation-only and leaves the 62.02% candidate
and its reference audit unchanged.
