# `quest_build_army_of_three`

Native target: `crimsonland.exe` at `0x00434ca0` (608 bytes).

Live Binary Ninja evidence recovers a fixed table of eleven formation entries,
with heading left untouched. The first nine enter from x `-64` in three
three-wave groups:

- template `0x15` at y 256, 512, and 768, triggers 500, 5500, and 15000;
- template `0x17` at y 768, 512, and 256, triggers 19500, 22500, and 26500;
- template `0x16` at y 256, 512, and 768, triggers 35500, 39500, and 42500.

Those entries all have count one. A template-`0x15` formation then appears at
the hardcoded coordinate `(512, 1152)`, trigger 52500, count three, followed by
a template-`0x17` formation at `(512, -256)`, trigger 56500, count three. The
vertical extremes are native constants rather than terrain-derived edges, and
the existing ports already preserve them.

Whole-vector construction and the shared inlined metadata setter reproduce the
native eight-byte temporary, template register reuse across each group, count
reuse, exact entry offsets, and epilogue. The candidate has the exact
116-instruction length and scores 86.21%. There are no auditable external
references in this constant-only builder. Its residual mismatches are VC6
scheduling among independent position temporaries and neighboring metadata
stores; no artificial dependencies or register forcing are used.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.

## 2026-07-27 focused family pass

Live Binary Ninja reconfirmed all eleven fixed formations and their constant
coordinates, templates, triggers, and counts. MSVC 6.0, 6.5, and 6.6 preserve
the 86.20689655172413% result and ten-instruction prefix; 6.5 Processor Pack
keeps the ratio but shortens the prefix to five, and 7.0 falls to
70.6896551724138%. `/GB`, `/G5`, `/G7`, `/Ox`, and `/Ob1` tie, while `/G6`
regresses to 56.89655172413793%.

`fixed-entry-sibling-shape-mutations.json` (SHA-256
`823a31fe3a281e61006e51edd6a3493530b934e61f586d5389179e00913fe2e1`)
recorded ten representative direct-position and direct-metadata variants.
Only entry-zero direct metadata is byte-neutral; all other variants lose
15.72 to 83.86 weighted bytes or remove the evidenced vector temporary.
No source change is retained. Validation remains 524.1379310344827/608
weighted bytes, an 83.86206896551732 gap, 116/116 instructions, prefix ten,
and references 0/0/0.

The two-argument metadata helper plus separate count assignment that improves
the looped `quest_build_the_unblitzkrieg` sibling does not transfer to this
fully unrolled table. The recorded `two-argument-helper-count-after` probe
preserves 116/116 instructions and the ten-instruction prefix but loses 68.14
fuzzy-weighted bytes, falling from 86.21% to 75.00%. The native overlap between
neighboring vector temporaries and complete metadata stores requires the
three-argument helper boundary here, so the canonical source is unchanged.
