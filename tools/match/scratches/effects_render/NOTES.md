# `effects_render`

Native target: `crimsonland.exe` at `0x0042e820` (740 bytes).

Live Binary Ninja evidence recovers the two effect-pool render passes, their
flag-`0x40` partition, per-entry rotation/scale transform, BGRA packing, camera
offset, and Grim2D batch state transitions.

Best verified candidate: **100.00%**, with 195/195 normalized instructions,
740/740 bytes, and masked references `38/0/0`, using Microsoft Visual C++ 6.5
with `/O2 /GB /W3 /GR-`.

## Recovered source shape

- The renderer selects the particle texture and draws the 512-entry effect
  pool in two batches. The first pass accepts active, non-negative-age entries
  with flag `0x40`; the second accepts the complementary active entries.
- Each entry builds the native 2x2 `{ cos, -sin, sin, cos }` rotation matrix,
  multiplies all four elements by the entry scale, and adds the camera offset
  to its canonical `effect_entry_t.position` aggregate.
- The offset uses the original mod SDK's vector house style: a two-float
  constructor that assigns the components in its body, invoked directly at
  the declaration site.
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
- The packed color output is owned once by `effects_render` and passed by
  reference into the inlined entry renderer. Rotation remains entry-local.
  That split is shared by both passes and reproduces the native scalar-slot
  ownership without constraining layout.

## Exact scalar-slot closure

At the preceding 94.87% baseline, VC6 assigned scalar rotation to `esp+0x8`
and the packed-color destination to `esp+0xc`; native uses `esp+0xc` and
`esp+0x8`, respectively, in both passes. Moving both scalars to the outer
function regressed to 89.74% and displaced the packed-byte staging object in
both passes. Moving only the packed-color result to the outer function is the
natural boundary supported by native reuse: staging remains at `esp+0x4`,
color becomes `esp+0x8`, rotation becomes `esp+0xc`, and all four regions
close simultaneously.

This is an ownership/lifetime correction, not an artificial layout device:
the ordinary caller local is passed by reference to the inlined renderer, and
there are no volatile qualifiers, dummy reads, dead expressions, or explicit
stack constraints.

## Recovery classification audit

The Binary Ninja pass partition, transforms, color conversion, vertex submits,
and Grim state transitions are all represented. Candidate and native each have
195 instructions and 740 bytes, all 38 references resolve, and the normalized
diff has no regions. Recovery is exact.

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

These sweeps closed aggregate-type and cv-lifetime explanations at the earlier
92.82% baseline without coercing stack layout. The later caller-ownership
correction resolves the slot assignment through a real source boundary.

## SDK vector-construction transfer

The original 2003 mod SDK and the neighboring UI renderer establish a distinct
non-POD vector form: the two-float constructor assigns `x` and `y` in its body,
and the caller constructs the first value directly at its declaration. Using
that form for the render offset raises the global match from **92.8205%** to
**94.8718%**, reduces the fuzzy gap from 53.128205 to 37.948718 bytes, and
removes the dependent offset-argument region in each pass. Instruction count,
exact prefix, and references remained 195/195, 37, and `38/0/0`. That left
only the two repeated rotation and packed-color stack-slot pairs subsequently
closed by caller-owned packed-output reuse.

## Caller-owned output interaction

Live native disassembly maps the repeated pairs at
`0x0042e8a6..0x0042e94f` and `0x0042e9f0..0x0042ea99`. Both passes reuse the
same `esp+0x4` packed-byte staging, `esp+0x8` packed output, `esp+0xc`
rotation, `esp+0x10..0x14` offset, and `esp+0x18..0x24` matrix workspace.

A complete transfer of both color and rotation to `effects_render` affects the
two passes identically and regresses from 94.8718% to 89.7436%. Transferring
only the packed output while leaving rotation local improves 94.8718% to
**100.0000%**, removes the 37.948718-byte fuzzy gap, and extends the exact
prefix from 37 to all 195 instructions. The two passes therefore interact
through one function-wide allocation decision, and the same single ownership
correction closes both rather than requiring per-pass spelling.
