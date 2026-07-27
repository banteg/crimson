# `quest_build_the_gathering`

Native target: `crimsonland.exe` at `0x004349c0` (725 bytes).

Live Binary Ninja evidence recovers a thirteen-entry fixed table. Heading is
left untouched for every entry:

- template `0x01` at (256,512), trigger 500 ms, count one;
- template `0x01` at (768,512), trigger 9500 ms, count two;
- template `0x3a` at (256,512) and (768,512), triggers 15500 and 24500 ms,
  count two;
- template `0x00` at (256,512) and (768,512), triggers 30500 and 39500 ms,
  count two;
- template `0x3c` at the four inset corners (64,64), (960,64), (64,960),
  and (960,960), all at 54500 ms with counts 2, 1, 2, and 1;
- template `0x3a` at (-128,512), trigger 90500 ms, count six;
- template `0x01` twice at (1152,512), triggers 99500 and 109500 ms,
  with counts four and two.

The absence of terrain-dimension references proves that the final three edge
coordinates are fixed. This corrected the Zig port, which previously scaled
their x coordinates with runtime width while the Python port already preserved
the native values.

The candidate matches all 134 native instructions with no static-reference
debt, scoring 89.55% with a 12-instruction exact prefix. An inlined combined
position-and-metadata setter is the strongest source shape: like native, VC6
materializes float coordinate literals through two eight-byte-frame temporary
slots while reusing integer constants across entries.

The residual consists only of legal independent-store scheduling. The
candidate occasionally loads the next entry's coordinate literal before
storing the current template id, and schedules a few final-entry stores across
the epilogue in a different order. Separate position assignment followed by a
metadata setter scored 88.06%; direct-field and statement-order variants did
not justify artificial barriers. No volatile state, dummy dependencies, or
register-forcing constructs are used.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.

## 2026-07-27 focused family pass

Live Binary Ninja reconfirmed all thirteen fixed entries and the absence of
terrain-derived final coordinates. MSVC 6.0, 6.5, and 6.6 tie at
89.55223880597015%; 6.5 Processor Pack falls to 87.31343283582089% and
7.0 to 61.94029850746269%. `/GB`, `/G5`, `/G7`, `/Ox`, and `/Ob1` tie,
while `/G6` regresses to 62.68656716417911%.

`fixed-table-sibling-shape-mutations.json` (SHA-256
`531327bfeb241ba0af52c0063dde69b5b0577ec065ea64e3c7e5d2fa0d1905c7`)
recorded eight representative variants. Expanding any of five calls to
position plus direct metadata is byte-neutral. Reordering the shared setter
loses 48.69 to 167.72 weighted bytes, confirming the existing position-first,
template-trigger-count form. No source change is retained. Validation remains
649.2537313432836/725 weighted bytes, a 75.74626865671644 gap, 134/134
instructions, prefix twelve, and references 0/0/0.
