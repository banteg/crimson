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
