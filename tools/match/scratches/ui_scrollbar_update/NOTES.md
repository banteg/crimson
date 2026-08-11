# `ui_scrollbar_update`

- Native function: `0x0043def0` (`1767` bytes, `479` instructions)
- Compiler profile: MSVC 6.5
- Current result: `82.22%`, `477` candidate instructions, `62/0/0`
  relocation references.

## Recovered behavior

The native helper owns the complete shared list-scrollbar interaction used by
the mods menu, both unlock databases, and the highscore screen:

- integer-align the caller-supplied origin and register keyboard focus;
- draw the list panel, optional track, proportional thumb, hover fill, and
  selected row state;
- handle wheel, arrow, page, track-click, thumb-grab, and thumb-drag input;
- clamp the scroll offset to the visible item range;
- render bounded visible rows, including the `\g` green marker;
- split tab-delimited fields in place and position each field with the caller's
  integer column offsets.

## Recovered state

The second argument is a `0x38`-byte state object:

| Offset | Type | Meaning |
| --- | --- | --- |
| `+0x00` | `float` | scroll offset |
| `+0x04` | `int` | hovered item |
| `+0x08` | `int` | selected item |
| `+0x0c` | `int` | visible rows |
| `+0x10` | `int[8]` | tab-column offsets |
| `+0x30` | `char **` | item strings |
| `+0x34` | `int` | item count |

Live caller disassembly proves the column array is integral: the highscore
screen stores raw immediates `10`, `30`, and `44` at `+0x10`, `+0x14`, and
`+0x18`, while this helper loads each entry for integer multiplication.

The byte at `0x004d11fa` is the private drag latch. The float at `0x004d11fc`
is the private thumb grab offset. Both have xrefs only inside this function.

The proven layout now lives in the shared `ui_scrollbar_t` type rather than
four caller-local replicas plus an untyped `float *` callee parameter. The
curated map also applies that type to the mods, highscore, and both unlock
screen static scrollbars. In the live Binary Ninja database this replaces
`id[0xd]`, `id[3]`, and `id[0xc]` with `item_count`, `visible_rows`, and
`items`, respectively. Recovering the input origin as `vec2f_t` and preserving
its two-field construction raises the honest MSVC score from `54.05%` to
`55.01%` with the same `59/0/0` reference agreement.

The visible-row loop now carries a typed `char **item` cursor instead of
reconstructing each item through a byte offset and cast. Native HLIL proves
that the loop advances both the selected index and an independent four-byte
item displacement. VC6 lowers the typed cursor to that same induction
variable, preserving the 470-instruction candidate, 55.0053% score, and
`59/0/0` reference audit exactly.

## Bounded geometry/input mutation evidence

Fresh mismatch regions and live Binary Ninja target
`3023:2:9499448411019345244` localize a stubborn region to proportional-thumb
geometry and drag input. Native uses integer memory operands directly:
`fild visible_rows; fidiv item_count` at `0x0043e183..0x0043e18b`,
`fild item_count` for the grab offset at `0x0043e305`, and
`fimul item_count` for drag scaling at `0x0043e347`. The recovered expressions
are semantically identical, but their candidate allocation carries additional
float temporaries and contributes to the larger frame.

The schema-1 `geometry-input-cast` sweep tested seven equivalent explicit- and
implicit-cast spellings across thumb height, thumb travel, grab offset, and
drag scaling. The persisted spec SHA-256 is
`e0cf8a4124fec96c5c2852ebc229217d3c25810edb458e0aef7caf234891b863`;
the unchanged baseline source SHA-256 is
`5e3a83de86b17b0d17299334cb15a7c5ad5776d1a46a7fc1ed4dc87a5d624c90`.
The complete harness ranking is:

| Rank | Mutation | Source SHA-256 |
| ---: | --- | --- |
| 1 | thumb travel: implicit multiplier | `0bdd73dd7bae60e01c6a4ef2843a3c20706d78a329ce73198918d3dfc226d17c` |
| 2 | thumb travel: implicit divisor | `2974ae337a7ca5df8595d4bc1f7e949accba8f24f662eab87574c5264ea9a4bb` |
| 3 | thumb travel: both implicit | `5c62d82542ecd7daec8e7326a95b1a126c0eeb4b1c97a86d494b3e4457e29c5c` |
| 4 | thumb height: numerator cast only | `8dc76532331c04547974047a7f021d716446e93732d9fcdbe125bd4aeaf80fdc` |
| 5 | thumb height: denominator cast only | `3011eb9a20fda6f0b4f6aa7c3515ea471eef393299548a99fcd3ebea22defb17` |
| 6 | thumb grab: implicit item count | `ba9e4a7b78e0302ecd09f75fbde88015298c4cad1d8d9125f101fb33e7f52b37` |
| 7 | drag scale: implicit item count | `6cb0ef2d3dd36b6c3cc0a0e532238c5520606d0509f97fa3db0452066a09aa94` |

Every single-site variant is byte-neutral: `55.00526870389885%`,
971.943098 fuzzy-weighted bytes, 470/479 instructions, prefix 0, and
`59/0/0` references. The record has `best_improves=false` and no winner.
Because no positive single justified interaction testing, the semantic source
remains unchanged. This rules out cast spelling as the cause of the localized
temporary layout.

## Native-guided mutation wave

The mutation harness was run against live Binary Ninja target
`3023:2:9499448411019345244` and the localized matcher regions. The wave
scheduled `668` bounded variants across `27` recorded sweeps; `544` compiled
successfully, while the remaining records are invalid partial combinations
from multi-site interaction specs. The all-error prototype scope sweep was
discarded rather than preserved as evidence.

The retained changes are semantic or directly native-evidenced:

- assigning the proportional thumb's `y` component before `x` gives VC6 the
  native interleaved x87 construction schedule at
  `0x0043e1b0..0x0043e1db`;
- declaring the interior height before the second panel draw but assigning it
  after that draw's position and color construction matches the native
  `0x0043dfae..0x0043e015` evaluation order. This is a source-lifetime fix,
  not a register-placement probe;
- drag scaling and clamping reload `item_count` and `visible_rows` from the
  recovered state object, matching `0x0043e331..0x0043e337`, while the row
  bounds reload the same fields at `0x0043e45a` and `0x0043e5af`;
- a complete 63-variant ablation proved the best interaction keeps cached
  locals for the grab divisor and first visible-row check, but retains the
  later direct field reloads;
- the tab loop indexes the recovered integral `column_offsets` array by the
  column counter, and reuses the incremented cursor when consuming a field.
  The latter removes the synthetic `consumed` local and follows the native
  update sequence at `0x0043e579..0x0043e592`;
- the leading-backslash policy is now precise. Native branches at
  `0x0043e4b7..0x0043e50c` set green for `\g`, set white only when the first
  byte is not a backslash, and leave the current color unchanged for other
  backslash escapes. The nested source correction is byte-neutral but fixes
  the recovered behavior.

The combined result moves from `55.00526870389885%`
(`971.943097997893` weighted bytes, `795.056902002107` gap, `470/479`
instructions, `59/0/0` references, `0x54` frame) to
`62.05450733752621%` (`1096.5031446540881` weighted bytes,
`670.4968553459119` gap, `475/479` instructions, `63/0/0` references,
`0x50` frame). That is a `7.049238633627364` percentage-point and
`124.56004665619552` weighted-byte improvement.

Negative sweeps rule out max-scroll type changes, cast spelling, temporary
constructor families, count declaration order, drag-block scheduling,
row-position copies, equivalent structured/goto loop forms, interaction
scopes, and alternate cursor/pointer lifetimes. A fresh profile matrix leaves
stock MSVC 6.0, 6.5, and 6.6 tied at the retained result; the Processor Pack
falls to `54.2766631467793%` and MSVC 7.0 to `30.2839116719243%`.

## One-shot track-coordinate lifetime

The track hit-test coordinate is consumed by one call, while the thumb
coordinate remains shared by its draw, hit test, fill, and drag calculations.
The source now publishes only the hit-test byte out of a short track-coordinate
scope. This preserves the genuinely shared thumb group while ending the
one-shot coordinate's lifetime at `ui_mouse_inside_rect`.

Native code constructs the track coordinate in the stack pair at
`0x0043e230..0x0043e260`, then immediately reuses that same pair for the hover
fill coordinate at `0x0043e264..0x0043e2c5`. Expressing that ownership lets
VC6 coalesce the slots: the candidate frame falls from `0x50` to `0x44` and
the score moves from `62.05450733752621%` to `63.10272536687631%`. Weighted
bytes increase from `1096.5031446540881` to `1115.0251572327045`, a gain of
`18.52201257861634`; instructions remain `475/479`, references remain
`63/0/0`, and the mismatch count remains 17 regions. The retained source
SHA-256 is
`398ceb159b2ace0922c370180cc6f76e5cb9e99be015e17d520bd9cabcfac774`.

## Remaining mismatch

The scratch remains `semantic-complete` with a `compiler` residual. MSVC now
allocates a `0x44`-byte frame versus the native `0x40` frame. The remaining
18 localized regions are dominated by temporary-object stack-slot coalescing,
the proportional-thumb x87 schedule, and late row-loop allocation. The final
candidate has `478/479` instructions and resolves all `64` audited references
with no mismatches or unresolved relocations.

## Hover-fill vector ownership (2026-08-09)

The exact list widget establishes the ordinary menu spelling for a coordinate
derived from another coordinate: base vector plus a short-lived vector offset.
Live native scrollbar disassembly shows that the track point at
`0x0043e230..0x0043e254` already has the current direct constructor's X-then-Y
schedule. The hovered thumb fill at `0x0043e264..0x0043e2c5` is the one
analogous owner: it derives both components from the shared thumb position and
is consumed by one draw call after the track hit test.

Spelling only that fill as `thumb_position + scrollbar_vec2_t(1, 1)` raises
the score from `63.10272536687631%` to `64.36781609195402%`. Weighted bytes
increase from `1115.0251572327045` to `1137.3793103448277`, a gain of
`22.3541531121232`; instructions move from `475/479` to `478/479`, and clean
references improve from `63/0/0` to `64/0/0`. The track, alternate fill, and
row constructors remain untouched. The function still has a `0x44` candidate
frame and the native fill computation is not yet fully scheduled after the
hover branch, so this is retained as a measured lifetime/allocation gain rather
than claimed as local exactness.

## Interaction lifetime and row induction (2026-08-11)

A fresh replay of `interaction-scope-lifetime-mutations.json` against the
current source invalidated the previous stopping point. The complete
31-variant interaction space found one five-site source shape that carries
`first_item` out of a short geometry/input scope, reloads `item_count` for the
thumb grab, ends the scope before row rendering, and reloads `visible_rows`
for the initial row check. It moves the retained result from
`64.36781609195402%` (`1137.3793103448277/1767` weighted bytes, no exact
prefix, `478/479` instructions, `64/0/0` references, `0x44` frame) to
`81.79916317991632%` (`1445.3912133891215/1767`, 26-instruction exact prefix,
`477/479`, `62/0/0`, `0x40` frame).

The reference-count reduction is not unresolved debt: all 62 remaining
references resolve cleanly, with zero mismatches and zero unresolved
relocations. It comes from the changed instruction shape. Live native
disassembly independently proves the direct field operands at the thumb grab
(`0x0043e305`), initial row check (`0x0043e396`), item-count loop bound
(`0x0043e45a`), and later visible-row bound (`0x0043e5af`), as well as the
native `0x40` epilogue frame. A complete 63-variant field-reload ablation left
this layout unbeaten; restoring only the cached thumb divisor loses about 14
weighted bytes, while the other cached-field interactions regress much more
or no longer compile because the locals correctly end with the scope.

The complete 26-variant `row-item-induction-mutations.json` sweep then proved
that this allocation wants the native four-byte item displacement explicitly,
not a typed pointer cursor. Carrying `item_offset = first_item * 4`, loading
through `(char *)state->items + item_offset`, and advancing by four adds
`7.393305439330334` weighted bytes without changing instruction or reference
counts. The retained final result is `82.21757322175732%`
(`1452.7845188284518/1767` weighted bytes, `314.21548117154816` gap), with a
26-instruction exact prefix, `477/479` instructions, a native-sized `0x40`
frame, and `62/0/0` references. Relative to the former 64.37% stopping point,
this is a `315.4052084836241` weighted-byte improvement.

Three additional current-source sweeps reached bounded neutral stopping
points: both thumb-height cast spellings (2/2), both text-loop entry
comparisons (2/2), and all six native-guided row-local declaration orders
(6/6). Their spec SHA-256 values are, respectively,
`5a70a015aeaaa050d4248ced309e15255ef5aad840efa80e5ddc77d925b10a67`,
`bd545e29642d04f29fd0c62d13c37c4f0f7cdddb60e838766962f0564340afda`,
and `4afbda504c9c91d4e03ad651491b673114e6e1d783370b5c46338b02aaaeb09e`.
The interaction, field-ablation, and row-induction spec hashes are
`00047dba22fb3600eb7a45f1ac1b2c1bbbb6a150ed36292dc84ad9a2d2f5126a`,
`0bedcf0dceb9e6a34460bf5c52b083bda2795c6a60271e698584143b4e5c6fa8`,
and `6694f8181fa156f8370bc7e5a501c5754612d441485301d510fc24b04cae32f3`.
The retained source SHA-256 is
`44355ff9cd417bac5fd92bcc7d9a3a826e4be77fab47c00f69cbebb7b73e893f`.

The scratch remains `semantic-complete` with an honest `compiler` residual.
The first residual is now after 26 exact instructions and is dominated by
temporary stack-slot placement; later regions remain x87 scheduling and row
loop allocation differences.
