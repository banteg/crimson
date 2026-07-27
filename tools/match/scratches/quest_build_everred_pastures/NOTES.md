# `quest_build_everred_pastures`

Native target: `crimsonland.exe` at `0x004375a0` (367 bytes).

Live Binary Ninja evidence recovers eight waves of four cardinal spider
entries. Templates `0x32`, `0x33`, `0x34`, and `0x35` arrive from the right,
left, bottom, and top edge midpoints respectively. Triggers are
`wave * 13000 + 1500` for zero-based waves, and each entry's count is
`wave + 1`. On wave index three, two additional template `0x1b` spiders spawn
at the top midpoint and at `(width / 2, 1088)`, both at 40500 ms/count eight.
The hard-coded 1088 y coordinate is distinct from the dynamic bottom edge.
The final output count is 34.

Keeping the entry cursor and emitted count together in a small builder
reproduces the native pointer and count inductions. Declaring the trigger at
its first use recovers the native position-first schedule and constant-13000
multiplication chain. The candidate also preserves signed width halving, x87
conversions, per-entry count increments, the conditional two-entry insertion,
24-byte record stride, all seven references, and the epilogue. It has the same
114 instructions, preserves a 30-instruction prefix, and scores 92.98%.

Publishing the first entry's metadata as three direct stores after calculating
its trigger raises the score from 92.11% by 3.219298 weighted bytes. This keeps
the source's natural template/trigger/count order while preventing VC6 from
hoisting the independent count store through the trigger multiplication. The
quest table and every control-flow decision are unchanged.

The residual is four independent VC6 choices: one metadata store crosses the
last trigger multiply, one width-plus-64 temporary uses EAX instead of EDX,
the resulting branch displacement differs by one byte, and the output pointer
uses ECX instead of EAX in the epilogue. A separate cursor/count, raw indexed
entries, an indexed builder, earlier trigger lifetime, `msvc6.5pp`, `msvc7.0`,
and `/G6` were checked. The exact-length default-profile shape is retained
without artificial dependencies or forced-register constructs.

## Recorded cardinal scheduling search

`cardinal-schedule-mutations.json` exhaustively evaluated 63 single and pair
combinations. The retained direct-store form gains 3.219298 weighted bytes
(spec
`ff9b975201386cc0e3a38f46714acea22a47b010bdf6f3bfcbbf5e0b7fc72ef7`).
`retained-trigger-shape-mutations.json` then evaluated 83 trigger-factor,
bottom-edge, and output-store singles/pairs with no further improvement (spec
`2f6096f4ce706ac8f5d973f79476719dc634fd23460321cce09ebd2db0d4ac4b`).
VC6.0, 6.5, the diagnostic-only Processor Pack profile, and 6.6 are
byte-identical at the retained score; VC7 is worse. Full results are recorded
in `experiments.jsonl`.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.
