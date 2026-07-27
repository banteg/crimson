# quest_build_spider_wave_syndrome

Native target: `crimsonland.exe` at `0x00436440` (95 bytes).

Recovered Tier 1 Quest 7's loop policy: 18 left-edge spider waves from 1500
through 95000 ms in 5500 ms steps, at `(-64, terrain_width / 2)`, using spawn
template `0x40` and `player_count * 2 + 6` creatures per wave.

The count-bearing local builder is the simplest source-shaped model found that
preserves the native independent base, entry-index, and trigger-time induction
variables. Native writes the fixed template and trigger before loading the
dynamic configured-player count. A two-argument metadata setter followed by a
separate count assignment recovers that distinction, matching the source shape
also evidenced in `quest_build_nesting_grounds`.

Scheduling the independent template and trigger stores before `pos.y`, while
leaving the dynamic count after it, raises the match from 83.87% to 87.10%
(82.74/95 weighted bytes). The candidate still produces the same 31
instructions and resolves both audited global references. The residual is
independent scheduling around the signed terrain-width conversion and loop
increments; the recovered loop, constants, arithmetic, record stride, and
output count agree. It remains a WIP, with no volatile state, dummy dependency,
or forced register/address construct.

## Recorded scheduling search

`entry-schedule-mutations.json` exhaustively tested 12 one-site source shapes.
The retained `metadata-before-y` variant gained 3.064516 weighted bytes (spec
`8604f0ef9e36861fc0e437661dc1ef9e0af9e31e50807506f47a447d68dd679d`).
A second complete 76-variant single/pair sweep over the helper body and loop
schedule found no further improvement (spec
`6e2507bf1e1ccf14a0d3a4ff8d955dcf8510d2f16d37048bbcc15fa48accdf11`).
VC6.0, 6.5, 6.5 Processor Pack, and 6.6 tie at the retained score; VC7 is
worse. All results are recorded in `experiments.jsonl`.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.
