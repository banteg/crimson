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
  to its position.
- A four-byte union reproduces the native alpha/red/green/blue conversion
  order and the four `__ftol` calls. The packed value is passed by address to
  `grim_submit_vertices_transform_color` with the entry's four vertices.
- Grim config slots `0x13` and `0x14`, the particle texture bind, both batch
  boundaries, and the final slot-`0x14` restoration all agree exactly.

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
