# `quest_build_gauntlet`

Native target: `crimsonland.exe` at `0x004369a0` (614 bytes).

Live Binary Ninja evidence recovers three phases and a temporary hardcore-mode
state adjustment. Hardcore mode adds four to the global player count before
building and subtracts four again on every return path. The phases are:

- `player_count + 9` template `0x0a` nests on a radius-158 ring centered at
  (512, 512), with triggers starting at 0 and advancing by 200 ms;
- `player_count + 9` four-entry template `0x41` waves at the right, left,
  bottom, and top edge midpoints, in that order. Triggers start at 4000 ms and
  advance by 5500 ms, while counts start at 2 and advance by one per wave;
- `player_count + 17` template `0x0a` nests on a radius-258 ring centered at
  (512, 512), with triggers starting at 42500 ms and advancing by 500 ms.

Both rings use `index * 6.28318548 / active_count`; separate cosine and sine
field assignments reproduce the native x87 strategy of retaining the numerator
while reloading and dividing by the global count twice. The four edge entries
recompute the signed integer width midpoint for every coordinate and use
`width + 64` and -64 as the outer bounds. Heading is left untouched throughout.

The candidate reproduces the exact 182-instruction body, the complete prologue
and hardcore restore paths, and all 25 audited references, scoring 80.22% with
a 31-instruction exact prefix. The residual is independent VC6 scheduling: the
candidate fills x87 and integer-conversion windows with metadata stores, while
the native delays those stores until each coordinate pair is complete. An
explicit cursor, post-increment reservation, combined position setter, and
shared angle temporary all degrade the proven register or x87 shape, so the
indexed direct-field version remains the strongest plausible source without
artificial dependencies or register forcing.
