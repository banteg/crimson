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
reuse, exact entry offsets, and epilogue. A continuous append count and five
explicit metadata-to-next-position publication boundaries raise the candidate
to an exact 116-instruction match. There are no auditable external references
in this constant-only builder.

## Recovery validation

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate now
matches the native instruction stream exactly.

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

## 2026-08-08 first-entry publication pass

The fixed-table house style from neighboring builders transfers at the opening
boundary: publishing entry zero through its trigger-field cursor raises the
score from 86.21% to 91.38% while retaining 116/116 instructions, the ten-
instruction prefix, and 0/0/0 references. The cursor changes VC6 allocation
for the complete unrolled table even though equivalent cursor forms at entries
one through ten are individually byte-neutral.

`trigger-cursor-mutations.json` (SHA-256
`5e2080a013d0197b44a2ae10de14b95ffd9c866256fa0c8cdd596fc3d3f03b35`)
bounds those ten remaining sites, and the complete result is recorded in
`experiments.jsonl`. The residual remains independent vector-temporary and
metadata scheduling rather than missing recovered behavior.

## 2026-08-08 append and publication-boundary recovery

One append count replaces the eleven fixed indices and output literal, raising
the retained candidate from 91.38% to 93.10%. Cross Fire then exposes the
remaining table dialect: publish the current template, construct the following
position, and only then publish the current trigger and count.

Applying that boundary at entries two, three, four, and six removes each
five-byte schedule gap. Directly publishing entry eight removes the final
larger tail region. Reconstructing the opening through the same boundary raises
the result to 99.14%, leaving only `mov ecx, 1` on the opposite side of the
following position construction. The candidate remains 116/116 instructions
with identical recovered values and table order.

## 2026-08-09 complete-entry house style

The SDK source consistently completes a record's scalar publication before
constructing the next aggregate. Moving the first entry's count assignment
ahead of the following position construction restores that source order; VC6
then interleaves the constructor load into exactly the native schedule. The
result matches all 608 bytes and all 116 instructions without a barrier,
dummy dependency, or register forcing.
