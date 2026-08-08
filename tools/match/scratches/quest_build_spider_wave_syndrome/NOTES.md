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

The canonical source completes `pos.y` before publishing template and trigger,
matching native's visible record-store order. VC6 still hoists those independent
metadata stores into the signed terrain-width conversion, leaving an honest
83.87% WIP with a 12-instruction exact prefix. The candidate produces the same
31 instructions and resolves both audited global references. The recovered
loop, constants, arithmetic, record stride, and output count agree, with no
volatile state, dummy dependency, or forced register/address construct.

## Recorded scheduling search

`entry-schedule-mutations.json` exhaustively tested 12 one-site source shapes.
The historical `metadata-before-y` variant gained 3.064516 weighted bytes but
moved the first mismatch three instructions earlier and contradicted native's
Y-before-metadata store order. The tradeoff-aware matcher now rejects it as an
automatic winner, and the position-first source is restored (spec
`8604f0ef9e36861fc0e437661dc1ef9e0af9e31e50807506f47a447d68dd679d`).
A second complete 76-variant single/pair sweep over the helper body and loop
schedule found no further improvement (spec
`6e2507bf1e1ccf14a0d3a4ff8d955dcf8510d2f16d37048bbcc15fa48accdf11`).
VC6.0, 6.5, 6.5 Processor Pack, and 6.6 tie; VC7 is
worse. All results are recorded in `experiments.jsonl`.

`typed-boundary-mutations.json` adds seven record, position, count, and
metadata alias shapes. Six compile byte-identically; the typed post-position
alias reproduces the restored 83.87% schedule. The plan SHA-256 is
`90f0ef11e7de5c0a0d58d6875672b32f5ac9c91a135ad44ee003bb24775b3e18`.
`/G5`, `/G7`, `/Ox`, and `/Ob1` also tie the retained `/GB` result, while
`/G6` regresses.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.
