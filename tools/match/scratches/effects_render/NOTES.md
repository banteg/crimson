# `effects_render`

Native target: `crimsonland.exe` at `0x0042e820` (740 bytes).

Live Binary Ninja evidence recovers the two effect-pool render passes, their
flag-`0x40` partition, per-entry rotation/scale transform, BGRA packing, camera
offset, and Grim2D batch state transitions.

Best verified candidate: 92.82%, with 195/195 normalized instructions and
masked references `38/0/0`, using Microsoft Visual C++ 6.5 with
`/O2 /GB /W3 /GR-`.

## Recovered source shape

- The renderer selects the particle texture and draws the 512-entry effect
  pool in two batches. The first pass accepts active, non-negative-age entries
  with flag `0x40`; the second accepts the complementary active entries.
- Each entry builds the native 2x2 `{ cos, -sin, sin, cos }` rotation matrix,
  multiplies all four elements by the entry scale, and adds the camera offset
  to its canonical `effect_entry_t.position` aggregate.
- A four-byte union reproduces the native alpha/red/green/blue conversion
  order and the four `__ftol` calls. The packed value is passed by address to
  `grim_submit_vertices_transform_color` with the entry's four vertices.
- Grim config slots `0x13` and `0x14`, the particle texture bind, both batch
  boundaries, and the final slot-`0x14` restoration all agree exactly.
- Each render pass keeps an interior `float *` induction register anchored at
  `effect_entry_t::color.g`. The two instruction-scoped cursor types are
  persisted separately, replacing anonymous structure offsets with stable
  field-relative indices without pretending either interior address is an
  `effect_entry_t *`.

## Remaining compiler residue

The candidate and target have identical instruction counts and reference
audits. VC6 assigns the scalar rotation and packed-color destination to the
opposite four-byte stack slots; that choice also moves one dependent offset
argument push. The same residue repeats in both otherwise matching passes.

Natural variants checked include declaration and initialization order, nested
scopes, return-value and output-pointer color helpers, a one-element color
array, aggregate offset initialization, an inline transform helper, and a
combined render-preparation helper. `msvc6.5pp` regresses to 85.28% and `/G6`
to 90.26%. None removes the allocator residue without explicitly coercing
local layout, so this remains an honest semantic WIP rather than a fakematch.

## Recovery classification audit

The Binary Ninja pass partition, transforms, color conversion, vertex submits,
and Grim state transitions are all represented. Candidate and native each have
195 instructions, and all 38 references resolve. The six localized regions
repeat the documented scalar/local-slot allocation and x87 scheduling choice
in the two equivalent passes. Recovery is therefore `semantic-complete` with a
`compiler` residual.

## Recorded first-residual sweeps

Live native disassembly at `0x0042e8a6` fixes the first mismatch precisely:
native stores rotation at `esp+0xc` and later materializes packed color at
`esp+0x8`; stock VC6 assigns those two real four-byte locals in the opposite
order. The matrix at `esp+0x18..0x24`, offset at `esp+0x10..0x14`, packed-byte
staging at `esp+0x4..0x7`, instruction count, and all references agree.

`render-local-slot-mutations.json` records six declaration, initialization,
and lifetime spellings. All six compile byte-identically at 92.82%, prefix 37,
195 instructions, references `38/0/0`, and a 53.128-byte fuzzy gap.

`color-helper-shape-mutations.json` records return-value and result-first
helper ABIs. Both complete definition/call pairings are also byte-identical;
the six deliberately incomplete or cross-paired combinations fail
compilation. No variant is retained. A fresh stock-VC6 matrix also leaves
`/G5`, `/Ob1`, and `/Ot` byte-identical to `/GB`; `/G6` and `/Oy-` regress.

## Recovered storage-type saturation

`render-storage-type-mutations.json` (SHA-256
`4908dab5bdd8f54aec989cbbb1a507a86798a6fd08fec1f61b4332b1d5e0420d`)
tests 19 complete single and pair variants around the two swapped four-byte
locals. Keeping packed color through its recovered union, an equivalent
one-word struct or array, qualifying rotation as a const value, and every
pair interaction are byte-identical to the canonical 92.82% object. A const
reference instead removes the native rotation spill and regresses to 41.45%;
it is not the recovered source shape.

`packed-color-output-mutations.json` (SHA-256
`36039e05e38c597f0cbabe9a7184cf62841f5eaae206e5b4e52c89de880002da`)
then carries the union type through the helper output, caller local, and final
Grim argument as one three-site interaction. The complete form is also
byte-identical at 195/195 instructions with references `38/0/0`; incomplete
type combinations correctly fail compilation.

These sweeps close the remaining aggregate-type and cv-lifetime explanations
without coercing stack layout. The repeated `rotation esp+0xc` versus packed
color `esp+0x8` native assignment is now saturated as a VC6 local-slot
allocator tie. A revisit needs new compiler or original-TU provenance rather
than further declaration, helper, or recovered-type permutations.
