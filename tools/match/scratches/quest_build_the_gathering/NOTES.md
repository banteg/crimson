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

## 2026-07-29 whole-table setter bound

Three complete sweeps close the remaining natural fixed-table helper families.
`whole-table-boundary-mutations.json` evaluates the exact sibling shape across
all thirteen entries, not just one call at a time. Position assignment followed
by a metadata helper regresses by 10.791044776119406 weighted bytes to 88.06%;
fully direct metadata regresses by 97.01492537313425 bytes to 76.12%. Its plan
SHA-256 is
`dd18586acaacdaac4040d542f2477c0e9c04047e03c8a7775525c2f6599949fb`.

`setter-shape-mutations.json` exhausts 27 single and paired constructor/setter
forms. Position by value, const value, explicit or forced inline, a returned
reference, and all constructor spellings are byte-identical; scalar position
copying regresses. Its plan SHA-256 is
`777abf41e950af6da03e0ae841111af57590ebb5ba6b3973e47f2b8e80ffb5c0`.

Finally, `setter-parameter-order-mutations.json` uses six semantically exact
call-signature permutations, including position-last and all relevant integer
orders. VC6 canonicalizes every one to the baseline byte stream. Its plan
SHA-256 is
`5d4db88df0c094aad8efc26a12a15606b07cbbf290b8ee8d7fc431cc8622d7cd`.
Together with the earlier store-order sweep, this bounds the constructor,
aggregate-copy, helper-boundary, parameter-order, and metadata-order source
families. The remaining legal store swaps are therefore retained as an honest
compiler residual.
