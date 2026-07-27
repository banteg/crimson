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

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.

## 2026-07-27 focused family pass

Live Binary Ninja reconfirmed both rings, every four-edge wave, and the
hardcore player-count restore paths. MSVC 6.0, 6.5, 6.5 Processor Pack, and
6.6 tie at 80.21978021978022%; 7.0 regresses to 75.06849315068493%.
`/GB`, `/G5`, `/G7`, `/Ox`, and `/Ob1` tie, while `/G6` falls to
79.12087912087912% and shortens the prefix.

`phase-metadata-shape-mutations.json` (SHA-256
`a656d52650447f821bad3097d938fc70364515e55c33386ea0f630a5481d17c2`)
recorded all 21 single and pair sibling-shape variants. Ring setters and
direct fields for every edge entry are all byte-identical, including their
pair interactions. No source change is justified. Validation remains
492.54945054945057/614 weighted bytes, a 121.45054945054943 gap,
182/182 instructions, prefix 31, and references 25/0/0.
