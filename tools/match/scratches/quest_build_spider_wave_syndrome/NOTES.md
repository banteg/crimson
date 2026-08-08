# quest_build_spider_wave_syndrome

Native target: `crimsonland.exe` at `0x00436440` (95 bytes).

Recovered Tier 1 Quest 7's loop policy: 18 left-edge spider waves from 1500
through 95000 ms in 5500 ms steps, at `(-64, terrain_width / 2)`, using spawn
template `0x40` and `player_count * 2 + 6` creatures per wave.

The count-bearing local builder preserves the native independent base,
entry-index, and trigger-time induction variables. Each record is addressed
separately as `builder.spawns[builder.count]`, completed through position,
two-field metadata, and dynamic count, then published by incrementing the
builder count. This is the same indexed-publication house style recovered in
the exact neighboring quest builders.

That ownership boundary prevents VC6 from hoisting metadata into the signed
terrain-width conversion and matches all 31 native instructions plus both
audited references exactly.

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

The preceding BN recovery accounts for the complete control-flow, constants,
record stores, induction policy, and output count. The candidate is an exact
normalized instruction and reference match, so no recovery or compiler
residual remains.

## 2026-08-08 exact indexed-publication recovery

Replacing the captured record pointer and pre-count publication with repeated
indexed entry expressions and a post-entry increment raises the candidate from
83.87% to 100%. The retained source matches 31/31 instructions with references
`2/0/0`. Source SHA-256:
`267fa4a552a9777a2b94d4ac6fbac332a5582f9bd2e023b6d52680ddbfde345d`.
