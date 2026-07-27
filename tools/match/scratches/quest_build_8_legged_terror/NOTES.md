# `quest_build_8_legged_terror`

Native target: `crimsonland.exe` at `0x00436120` (213 bytes).

Live Binary Ninja evidence recovers the opening SpiderBoss at
`(terrain_texture_width - 256, terrain_texture_width / 2)`, template `0x3a`,
1000 ms, count 1. It is followed by four-corner waves at `-25` and `1049`,
using template `0x3d`. Triggers run from 6000 while below 36800 in steps of
2200. The top-left and bottom-left entries use the player count; the other two
use count 1. The builder therefore emits 57 entries.

Keeping the cursor and emitted count together in the builder object prevents
VC6 from folding the final count and recovers the native count-register
increments. The entire repeated-wave loop matches instruction-for-instruction.
Constructing the advancing builder cursor before the opening entry's independent
metadata stores raises the candidate from 92.65% to 95.59% (203.60/213 weighted
bytes). It has the same 68 instructions; all residuals remain confined to
scheduling in the one-time opening entry, where the far-edge constant and
three independent metadata stores move around the integer-to-float `pos.y`
conversion. No dependency is introduced to force that ordering.

Binary Ninja now gives the four-corner loop cursor a two-entry presentation
view. Two consecutive pairs expose all four waves as named
`quest_spawn_entry_t` fields while retaining the native 0x60-byte cursor step;
the compiler-facing builder now uses that same canonical record and its flat
position members. The migration is byte-neutral at 68/68 instructions and
the retained 95.59%.

## Recorded opening-entry search

`opening-cursor-lifetime-mutations.json` exhaustively tested ten cursor and
opening-record schedules. The retained `builder-before-metadata` form gained
6.264706 weighted bytes (spec
`3fa4526a8f2707fac31753629331eca0a0c2e807a890096cb017387f8e21a361`).
A complete 34-variant helper/metadata single-pair sweep found no further
improvement (spec
`617fd6d5ad2e0702b36e153fe64ab488d15b84d0d1e5499ad7201e09db464a22`);
five declaration-order replays were byte-neutral (spec
`928a6766984f77baed2f4f53a4ef494ee773fddb7e15ba7e2ccec32b3d49dbc5`).
VC6.0, 6.5, 6.5 Processor Pack, and 6.6 tie; VC7 is worse. The complete
results are recorded in `experiments.jsonl`.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.
