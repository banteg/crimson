# `quest_build_land_hostile`

Native target: `crimsonland.exe` at `0x00435bd0` (239 bytes).

Live Binary Ninja evidence recovers four pale-green alien entries: the bottom
edge midpoint at 500 ms/count 1, bottom-left at 2500 ms/count 2, top-left at
6500 ms/count 3, and top-right at 11500 ms/count 4. The first position uses
`terrain_texture_width / 2` and `terrain_texture_height + 64`; the three corner
positions are `(-64, 1088)`, `(-64, -64)`, and `(1088, -64)`.

An inlined two-float constructor plus entry `set` method reproduces the
native's 12-byte local frame, integer-to-float conversions, float-word copies,
and shared template register. Publishing the first and fourth entries through
their trigger-field cursors recovers two of the three cross-entry scheduling
boundaries. The candidate has the same 53 instructions, scores 98.11%, and
matches the first 37 instructions exactly. The sole residual is entry two's
template store crossing construction of entry three's x-coordinate temporary.

`entry-boundary-mutations.json` records four complete whole-builder
alternatives: aggregate and scalar direct metadata, a shared-template direct
form, and metadata-before-position ordering. None improves the 92.45%
baseline; the direct aggregate forms regress to 81.13%. The plan SHA-256 is
`49c496601413ecac2798903dbfbf0bb78f837635a420e88ccd2d1db0f79def45`,
so these negative results remain reproducible after future source refactors.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.

## Setter-shape exact-tail bound (2026-07-29)

Two focused sweeps cover the remaining inlined-setter distinctions. The
four-variant parameter/copy sweep shows that const-reference, by-value, and
const-by-value aggregate copies are byte-identical. Scalar member copies
remove fourteen native instructions, reset the exact prefix, and lose
122.24487284659558 weighted bytes. Its spec SHA-256 is
`1de9b7619d488d3fcdb36d1a36ea7864e7b8ba45d61d5a8a180d0bdd470c081d`.

The five non-baseline metadata assignment permutations all regress while
preserving the native 53-instruction count and `2/0/0` references. Losses
range from 4.509433962264154 to 22.54716981132077 weighted bytes. Its spec
SHA-256 is
`bffc23aaee38cb1510a07dc7588abe647e22e381e0b0bc0a827da3d7e10516b6`.
Combined with the earlier whole-entry audit, this bounds the natural
temporary, aggregate-copy, and metadata-order source families. The canonical
all-setter candidate remained unchanged at that point.

## Split-publication improvement (2026-08-08)

The whole-entry sweeps changed every boundary together. Replaying the
quest-builder house style one entry at a time shows that entries zero and
three instead publish position through the record view and metadata through a
trigger-field cursor. Retaining those two boundaries improves the candidate
from 92.45% to 98.11%, extends the exact prefix from 19 to 37 instructions,
and preserves 53/53 instructions and references `2/0/0`. Applying the same
form to entry two is byte-neutral; direct metadata and named next-position
forms regress. Retained source SHA-256:
`b2ff49d64f7550fbbcb552022d4baeaaf9f237ff4c3bfbc90a7e627fc86df4b8`.
