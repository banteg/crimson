# ui_element_set_rect

Native target: `crimsonland.exe` at `0x00419ba0..0x00419cfc` (348 bytes).

This is an evidence-backed semantic reconstruction, not an exact match.
Microsoft Visual C++ 6.5 with `/O2 /GB /W3 /GR-` produces 93 normalized
instructions against 91 native instructions, with 77.17% similarity, a
20-instruction exact prefix, and masked references `6/0/0`. The earlier full
compiler/flag sweep found no exact profile flip, so the mutation pass retained
the stock VC6.5 `/O2 /GB` profile.

## Recovered source shape

- The first argument is the `0xe8` quad payload also accepted by
  `ui_element_load`, not the much larger runtime `ui_element_t` inferred by
  the old decompiler type. Eleven native callers pass menu/sign template
  blocks with this layout. The matching map now records the owning
  `ui_menu_item_subtemplate_block_t *` type, so Binary Ninja presents the
  first slot through its named fields instead of unrelated runtime-element
  offsets.
- Each `0x1c` slot is a transformed vertex: XY position, adjacent Z/RHW
  floats, packed color, and UV. Grouping Z/RHW as a two-float aggregate is
  supported independently by the effect and Grim2D vertex surfaces and
  recovers the native loop's ESI/EDI constant copies.
- The first four positions form a one-pixel-inset rectangle: `(1,1)`,
  `(width-1,1)`, `(width-1,height-1)`, and `(1,height-1)`. UVs apply the same
  one-texel inset using `1/width` and `1/height`.
- All four vertices receive white (`0xffffffff`), `z = 0.5`, and `rhw = 1.0`,
  then the supplied two-float offset is added to every XY position.
- Native x87 stores establish the source assignment order for the bottom
  vertices as slot 3 followed by slot 2. That order keeps the candidate's
  floating-point evaluation and store schedule closest to the executable.
- Declaring both inverse dimensions and the real `right`/`bottom` edge scalars
  before the vertex stores is semantically direct and recovers the native
  12-byte frame. VC6 schedules the first 20 normalized instructions exactly
  even though the source declarations precede the first position assignment.

## Remaining mismatch

Native and candidate now both reserve 12 local bytes and have identical
prologues and epilogues. The candidate has two extra normalized instructions.
The first residual region begins after the 20-instruction prefix and contains
equivalent x87 stores for `right`, `bottom`, and the four position aggregates.
The second is UV/depth temporary scheduling. The last is the four-vertex loop:
the two-result source makes VC6 load both vertex coordinates before their
offsets, but it calculates Y before X and keeps both results live until the
post-increment stores. Native calculates and stores X before calculating Y.
The color, depth copy, offset loads, stride, trip count, and values are
unchanged.

No inline assembly, volatile state, dummy reference, forced address, or
layout-only arithmetic is used.

The loop induction value defined at `0x00419bdc` is the address of the first
vertex Y coordinate. Binary Ninja keeps that exact `float *` value as
`vertex_y_cursor`; the name is instruction-anchored and does not pretend that
the interior cursor owns the surrounding quad.

## Recorded mutation sweep

`local-lifetime-mutations.json` is a schema-1, one-site specification with
eight plausible alternatives covering declaration order, named `one`,
`right`/`bottom` scalars, and early or late depth declaration/aggregate
initialization. A recorded `--max-changes 1` sweep evaluated all 8/8 possible
variants with no truncation. Its spec SHA-256 is
`117c45ed04f7267e2fa64ff6936e3db61f9355013cb77e6066674eacffda7f80`;
the complete result is in `experiments.jsonl`.

| source | match | candidate/native | prefix | fuzzy-weighted bytes | refs |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline | 43.72% | 92/91 | 0 | 152.13 | `4/0/0` |
| `compute-scalars-before-stores` | 75.00% | 93/91 | 20 | 261.00 | `6/0/0` |

The retained winner has source SHA-256
`72a6844226e9103b628b034a2e3cae4af7afd43cf834ef1bd96a5ad15a4b90a2`
and reduces the fuzzy gap from 195.87 to 87.00 bytes. Moving only the depth
declaration late or using a late aggregate initializer was neutral at 43.72%.
Early aggregate initialization regressed to 42.62%; the two named-`one`
variants reached 41.30%; and named `right`/`bottom` without the winning
declaration order reached 36.96%. Thus the gain comes from the evidenced
combined scalar lifetime/order, not from a forced stack object.

### Add-order follow-up

`vec2-add-order-mutations.json` scopes one site to the two additions in
`ui_vec2_t::operator+=`. It tests self-first and commuted spelling on both
axes, both mixed-axis spellings, and a two-result temporary form. A second
recorded `--max-changes 1` sweep evaluated all 5/5 variants with no
truncation. Its spec SHA-256 is
`a0268ead913540ee3c783beb2511455b5237fc6e0f7c049be522b1953a615ad1`.

| source | match | candidate/native | prefix | fuzzy-weighted bytes | refs |
| --- | ---: | ---: | ---: | ---: | ---: |
| improved baseline | 75.00% | 93/91 | 20 | 261.00 | `6/0/0` |
| `two-result-temporaries` | 77.17% | 93/91 | 20 | 268.57 | `6/0/0` |

All four direct or mixed source-order spellings compile identically to the
75.00% baseline. The retained two-result form improves the fuzzy score by 7.57
bytes and reduces the gap from 87.00 to 79.43 bytes without changing the
native 12-byte frame, instruction count, prefix, or reference audit. Its
source SHA-256 is
`1e04d60d1711e24f2778516f7fed1b4828d250188fa404e3945206072b368be7`.

## Recovery classification audit

A fresh focused `--regions` run confirms **77.17%**, 93/91 candidate/native
instructions, prefix 20, and `6/0/0` references. The anti-fakematch validator
passes. Live Binary Ninja on `crimsonland.exe.bndb` confirms the four inset
positions and UVs, the shared white/depth values, the native 12-byte local
frame, and the four-step offset loop.

The complete geometry and loop behavior remain recovered without volatile
state, dummy address-taking, fake arithmetic, or register forcing.
Classification: `RECOVERY=semantic-complete`, `RESIDUAL=compiler`.
