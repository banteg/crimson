# ui_element_set_rect

Native target: `crimsonland.exe` at `0x00419ba0..0x00419cfc` (348 bytes).

This is an exact, evidence-backed semantic reconstruction. Microsoft Visual
C++ 6.5 with `/O2 /GB /W3 /GR-` produces all 91 native normalized
instructions, a full prefix, and masked references `6/0/0`.

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
  `(width-1,1)`, `(width-1,height-1)`, and `(1,height-1)`.
- The native UVs contain an asymmetric lower-left corner:
  `(1/width,1/height)`, `(1-1/width,1/height)`,
  `(1-1/width,1-1/height)`, and `(1/width,1-1/width)`. In particular, slot 3
  uses the width-derived lower U value for V as well. This appears to be a
  native typo, but preserving it is required for behavioral and byte parity.
- All four vertices receive white (`0xffffffff`), `z = 0.5`, and `rhw = 1.0`,
  then the supplied two-float offset is added to every XY position.
- Native x87 stores establish the source assignment order for the bottom
  vertices as slot 3 followed by slot 2. That order keeps the candidate's
  floating-point evaluation and store schedule closest to the executable.
- Declaring both inverse dimensions and `right` before the top position pair,
  then materializing `bottom` before the lower pair, recovers the native
  lifetime boundary and 12-byte frame. VC6 now schedules the first 57
  normalized instructions exactly.
- In the offset loop, assigning the computed X value before evaluating Y
  reproduces the native load/add/store sequence on both axes.

## Exact closure

The former three-instruction UV/depth residual was a recovery error, not a
compiler residual. Live Binary Ninja data flow shows that `0x00419c63` saves
`1 - 1/width`, `0x00419c88` reloads it into EDX, `0x00419cab` writes that same
value to slot 3 V, and only `0x00419cae` writes `1 - 1/height` to slot 2 V.
The prior source imposed symmetric V coordinates and therefore made VC6 remove
the native copy moves.

Restoring the native asymmetry and expressing both lower UVs as aggregates
reproduces the executable exactly: 91/91 normalized instructions, full prefix,
348/348 fuzzy-weighted bytes, and references `6/0/0`. Native and candidate
also share the 12-byte frame, prologue, epilogue, depth/color initialization,
loop stride, trip count, and branch displacement.

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

### Native scheduling follow-up

Three further complete mutation sweeps retain successively narrower source
lifetime and store-order changes:

| source | match | candidate/native | prefix | fuzzy-weighted bytes | refs |
| --- | ---: | ---: | ---: | ---: | ---: |
| prior baseline | 77.17% | 93/91 | 20 | 268.57 | `6/0/0` |
| X temporary, then direct Y | 79.35% | 93/91 | 20 | 276.13 | `6/0/0` |
| top position pair before `bottom` | 85.25% | 92/91 | 57 | 296.66 | `6/0/0` |
| symmetric lower-left aggregate, lower-right components | 87.15% | 88/91 | 57 | 303.28 | `6/0/0` |

- `vec2-add-sequencing-mutations.json` evaluates seven complete loop-add
  schedules. The retained X-temporary/direct-Y form is tied with the symmetric
  Y-temporary spelling, improves the weighted score by 7.57 bytes, and makes
  the native X load/add/store precede the Y load/add/store. Spec SHA-256:
  `5d4f4e7bdb4d13df9a0d2456c02a902d3ac338cd0abde48583a94102fee94e90`.
- `position-schedule-mutations.json` evaluates five placement and
  materialization schedules. Moving only the real `bottom` calculation after
  the top position pair removes one candidate instruction, extends the exact
  prefix from 20 to 57, and gains 20.53 weighted bytes. Spec SHA-256:
  `91321244a607c6fee5ccf5a3ee0e13b6a59d61ba4df233f3e32fac661d23f79d`.
- `uv-bottom-pair-mutations.json` evaluates seven lower-pair storage shapes.
  Keeping slot 3 as an aggregate and writing slot 2 through its two named
  components removes four candidate instructions and gains another 6.63
  weighted bytes. Spec SHA-256:
  `2a9044aad5b2658624d1dd909ee60794b119322821ac46252176e461d9bbb131`.

Three recorded negative matrices bounded the three-instruction tail while the
source still assumed symmetric lower V coordinates.
The 11-variant depth-lifetime interaction sweep is byte-neutral at best (spec
SHA `b61099cc508093b5be89afaa7ecd80f4a453299693aaf0ff28c94ba57d35e4de`);
the seven slot-2 scalar/local copy forms are also neutral at best (spec SHA
`642123d4699ffc1bfb36a2342ca2fd9281f2d8bc2aa293dc6c2e034d3deef5ba`);
and all 17 explicit assignment-operator interactions regress, with even the
implicit aggregate-only form returning to 85.25% (spec SHA
`b823a7f89feec5ed6001199704bbcfdc0a196acf2cc9f227ba49b2d0a2995894`).

A 30-profile matrix covered MSVC 6.0, 6.5, 6.5pp, 6.6, and 7.0 with `/O2 /GB`,
`/G5`, `/G6`, `/Oy-`, `/O1`, and `/Ox`. Before correcting the UV semantics,
stock VC6.0/6.5/6.6 `/O2 /GB`, `/G5`, and `/Ox` tied at 87.15%; this negative
result helped rule out a profile override.

## Recovery classification audit

A fresh focused `--regions` run confirms **100%**, 91/91 candidate/native
instructions, full prefix, and `6/0/0` references. The anti-fakematch validator
passes. Live Binary Ninja on `crimsonland.exe.bndb` confirms the four inset
positions, the asymmetric lower-left UV, the shared white/depth values, the
native 12-byte local frame, and the four-step offset loop.

The complete geometry and loop behavior remain recovered without volatile
state, dummy address-taking, fake arithmetic, or register forcing.
Classification: exact match.

`uv-depth-interactions.json` adds a complete 35-variant, up-to-three-site
matrix over lower-right UV aggregate materialization and early/late depth
storage (spec
`29a2f5120440fbc5123849327581e91f0c641dcd09634d0928b545a376859db9`).
Under the former symmetric-UV model, the best variants are byte-neutral at
**87.15%**. Aggregate UV forms add four instructions and regress; removing the
depth storage loses two instructions; the remaining incomplete site
combinations fail compilation as expected. This negative result no longer
describes the corrected asymmetric source.

`uv-value-reuse-mutations.json` tests six ways to derive the lower-right UV
from already written endpoints. Reusing the upper-right X and lower-left Y
raises the aggregate score by 5.61 weighted bytes, but is rejected: it reads
vertex fields while native reads stack-held UV temporaries, moves the first
mismatch earlier, drops the exact prefix from 57 to 48, and shortens the
candidate from 88 to 87 against 91 native instructions. The other five forms
regress. This is recorded as a misleading aggregate-only improvement rather
than retained as source evidence.

### Native-asymmetry closure

`lower-left-v-native-asymmetry-mutations.json` tests seven native-evidenced
forms of the lower UV pair. The complete, untruncated `--max-changes 1` sweep
is recorded in `experiments.jsonl`; its spec SHA-256 is
`c5ef54f8530545faef76715d82d786fb6edd55a42f1ceabe47cdabcb6176ea62`.

| source | match | candidate/native | prefix | fuzzy-weighted bytes | refs |
| --- | ---: | ---: | ---: | ---: | ---: |
| symmetric baseline | 87.15% | 88/91 | 57 | 303.28 | `6/0/0` |
| asymmetric mixed aggregate/components | 94.97% | 88/91 | 63 | 330.50 | `6/0/0` |
| asymmetric two aggregates | **100%** | **91/91** | **91** | **348.00** | `6/0/0` |

The retained exact winner has source SHA-256
`ead99e33f50859e1e7bef17f3a568ffcc57ff22291dcd33e554cb2e5f98ac13a`.
It adds the three native copy instructions and removes the entire 44.72-byte
fuzzy gap by correcting the slot 3 V value, not by introducing artificial
dependencies.
