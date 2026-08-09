# `player_render_overlays`

Native target: `crimsonland.exe` at `0x00428390` (4,582-byte manifest extent,
1,148 instructions in the current Binary Ninja analysis).

This scratch is an evidence-led reconstruction of the complete per-player
render callback. It retains the early suppression and transition/state gates,
Radioactive aura, dead and alive trooper sprite passes, multiplayer tints,
shield layers, muzzle flash, and the final segmented target-trail branch.

The reconstructed control flow and constants are corroborated by live Binary
Ninja HLIL/disassembly and the retained IDA artifact. The modern world renderer
also independently carries the active aura, trooper, shield, and muzzle-flash
passes. The native callback uses a float at player offset `0x98` to gate the
target trail. A live reference inventory found only the constructor's zero
store and this x87 load/`0.25f` comparison, so the shared header now records
the proven `float` type while conservatively retaining the reserved field name.
The scratch can therefore use the field without a bit reinterpretation.

The target-trail selector is initialized to perk id zero by the native perk
database constructor and has no other writer in the executable. The branch is
therefore preserved as recovered native source shape, but deliberately not
given a speculative gameplay name or treated as a required modern-port feature.

With the standard `msvc6.5 /O2 /GB` profile, the complete candidate is an
`85.60%` WIP (`1,137/1,148` instructions, prefix `9/1,148`). The target and
candidate prologues are identical through the `sub esp, 0x2c` local-frame
allocation. Masked-reference auditing reports `325/0/0`: every aligned symbol
resolves and agrees without a speculative alias.

The target-trail direction is a two-component value passed in place as both
the destination and immutable source of `D3DXVec2Normalize`. Its live
prototype is now the proven stdcall
`vec2f_t *(vec2f_t *, const vec2f_t *)`, replacing Binary Ninja's former cdecl
`float *(float *, float *)` guess. Propagating that contract through this
custom vector value remains matcher-neutral. The later target-direction
assignment correction described below first moved the score to `85.20%`;
the alive-torso value-shape recovery raises the current score to `85.60%`
with a `325/0/0` reference audit.

The muzzle-flash weapon-flag arms deliberately retain their identical
`grim_draw_quad` calls. Native reloads the player size in each arm and pushes
each arm's size and position arguments before tail-merging at the shared
virtual call; expressing the call once after the branch instead produces a
shorter, structurally different VC6 lowering. Recovering the branch-local
calls raised the candidate from `83.00%` and `1,134` instructions to `83.88%`
and `1,141` instructions.

The scoped `camera_offset:camera_offset_x` alias only identifies the scratch's
two-float vector declaration with the proven native x/y global pair. A tested
`msvc6.5pp` override fell to `70.34%`; the default VC6 backend is retained.
The remaining differences are honest x87 temporary placement, vector-expression
lowering, register scheduling across the long sprite pipeline, and the
target-trail loop's local-slot choices rather than omitted render branches or
unresolved references.

## Recorded native-grounded mutation sweeps

A fresh live Binary Ninja bundle from target
`3023:2:9499448411019345244` has SHA-256
`ebd9f5a6aaaef0d4fa661b0f4c12d8fa129df7392302ae5b7c4556d710330efb`.
The nominal first mismatch remains the early-return branch displacement after
the nine-instruction exact prefix. The first substantive local divergence is
inside the inlined UV helper at native `0x004285e8`: native uses its reusable
two-float `var_8` object and stack slots `esp+0x34`/`esp+0x38`, while the
candidate schedules equivalent temporary values through lower slots. The
target-trail guard at `0x004293d4` also keeps the `0x98`-stride creature index
in a scaled `[ecx*8+base]` address, whereas the candidate materializes the
final byte offset first. These observations bounded two schema-1 single-site
sweeps.

The retained source SHA-256 is
`536084d3873edf98ae7516d8dff3abfab963c71683719033360850c9a17d8517`:
83.8794233%, a 738.645-byte fuzzy gap, 1,141/1,148 instructions, prefix 9,
and `326/0/0` references.

`localized-lifetime-mutations.json` has SHA-256
`c6c42f8e74ef48a86cbce304ba9b776da40aa01d8d3721c451655f35d420285d`.
All seven possible one-change variants were evaluated:

| rank | variant | source SHA-256 | ratio | fuzzy gap | instructions | prefix | refs ok/unresolved/mismatch | result |
| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| 1 | `uv_end_vector_lifetime/named_uv_end` | `a40d5d155340fa343441ceb7e55ebda53cad115b758a6f6b67b4c9ea46b5d5a1` | 83.8794233% | 738.645 | 1,141 | 9 | 326/0/0 | byte-identical |
| 2 | `recoil_vector_lifetime/named_scalars_then_constructor` | `09962bec13e9e080cd81736060008b3626aebb279538b872e83a08215e0eef10` | 83.8794233% | 738.645 | 1,141 | 9 | 326/0/0 | byte-identical |
| 3 | `recoil_vector_lifetime/assigned_components` | `8557817a19059c8e023692096c0b5ec20a8aa7791e3bb3fdfcdb7c2c5fb540f4` | 83.4280717% | 759.326 | 1,139 | 9 | 321/0/0 | rejected |
| 4 | `uv_end_vector_lifetime/named_uv_begin_and_end` | `2059a26872db5028ec0a50f80112ea22d9555fc741fa1b8f486bf68918f8b529` | 82.4706394% | 803.195 | 1,151 | 9 | 311/0/0 | rejected |
| 5 | `target_distance_guard_shape/direct_named_deltas` | `a61e44f55b11a46b73ddb46c24bab9e78575acce1eb8947a6cd2b36762fdb226` | 82.2707424% | 812.355 | 1,142 | 9 | 326/0/0 | rejected |
| 6 | `target_draw_origin_lifetime/named_scalar_origin` | `346e244a0f4157d6fdcff4794a93c2be53dfc517e40ae17abb8b5b40e728739e` | 81.2581913% | 858.750 | 1,141 | 0 | 323/0/0 | rejected |
| 7 | `uv_end_vector_lifetime/assigned_uv_end_components` | `4fae6fe05434f865de815d14dbb6bfa75dc5d4e8918121f2b7476c5294afea07` | 81.0975610% | 866.110 | 1,148 | 9 | 303/0/4 | rejected |

`target-trail-shape-mutations.json` has SHA-256
`98fe9b56958db5ab21693467f3307d38af7f86a877fa5ce32ae896f010b587ab`.
All four possible one-change variants were evaluated:

| rank | variant | source SHA-256 | ratio | fuzzy gap | instructions | prefix | refs ok/unresolved/mismatch | result |
| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| 1 | `target_trail_coordinate_operand_order/offset_first` | `29cdda677c18f15ae02632fe1fb981baf3d3114a2face8f408cc94564dc2d2f0` | 83.8794233% | 738.645 | 1,141 | 9 | 326/0/0 | byte-identical |
| 2 | `distance_call_field_anchor/named_target_index` | `ba7804e38611f18a438ecb040d14afd1149cefe8b167c4f2934b9c7c24d1aaf0` | 83.8794233% | 738.645 | 1,141 | 9 | 326/0/0 | byte-identical |
| 3 | `distance_call_field_anchor/anchor_at_pos_x` | `ad32792160e842b8f58ac3bd8efa92d7ca9748dfc9f23504c26a0d5b45fe0918` | 83.8794233% | 738.645 | 1,141 | 9 | 326/0/0 | byte-identical |
| 4 | `distance_helper_parameter_passing/vectors_by_value` | `784031e0aec15eb35a30515eda10ff3d174c74146980f7468764097c5cca9528` | 82.9777971% | 779.957 | 1,149 | 0 | 324/0/0 | rejected |

No individually positive site exists, so no interaction was eligible. Both
sweeps have complete one-change coverage, `best_improves=false`, and zero
unevaluated planned combinations. No source variant or modern-port change was
retained. Those two complete records are the first two entries in
`experiments.jsonl`.

## Muzzle-flash lifetime follow-up

The largest previously unswept local region is the two-arm muzzle-flash quad
at native `0x004291fb-0x0042930d`. Live disassembly confirms that the
weapon-flag-four arm retains its quarter-size value across both coordinate
calculations, stages the output through `esp+0x34` and `esp+0x38`, and loads
the Grim interface before the quad arguments. The other arm similarly keeps
its half-size and full-size values in separate stack slots before both arms
join at the virtual draw call.

Two complete native-grounded sweeps reject ordinary source-shape alternatives:

- `muzzle-interface-lifetime-mutations.json` tested shared and arm-local Grim
  interface pointers before and after the half-size calculation. All three
  variants regress by 14.341 to 30.362 fuzzy-weighted bytes and lose one or
  two aligned references. Spec SHA-256 is
  `48e9bf867b43a609a0c7a3708f7877e6c81d372ea44c9d2ba4b7d9ada798e676`.
- `muzzle-coordinate-shape-mutations.json` tested explicit x/y lowering in
  either arm and in both arms together. The complete three-variant interaction
  sweep loses 31.035 to 64.012 weighted bytes, removes 3 to 17 candidate
  instructions, and loses 2 to 9 aligned references. Spec SHA-256 is
  `0bbdaee1085c7d4a20e5c960b25dd7e642a41ad52d177740db6303961466ff9a`.

The existing vector-expression and direct-interface form is therefore
retained. Final source SHA-256 remains
`536084d3873edf98ae7516d8dff3abfab963c71683719033360850c9a17d8517`:
83.8794233%, 3,843.355/4,582 fuzzy-weighted bytes, a 738.645-byte gap,
1,141/1,148 instructions, prefix 9, and `326/0/0` references. That
four-record `experiments.jsonl` prefix had SHA-256
`f501de07b8b307a96e75eb62e999c0a3dfe6f6280aca44b7206b51d59011520b`.

## Additional frame-layout controls

Four more bounded sweeps tested the ordinary source mechanisms most likely to
explain the remaining reusable-local and target-trail layouts:

- all eight declaration-order permutations were byte-identical
  (`function-local-order-mutations.json`, spec SHA-256
  `d8445517e6dc8e9b8487a381ff62cf1e77a43acc3480d7a2c6db8b442df04bf0`);
- five vector copy/destructor/assignment variants found neutral explicit-copy
  forms, while explicit assignment regressed by 552.172 weighted bytes
  (`vector-special-member-mutations.json`, spec SHA-256
  `7934c3ccde32029c89994dc20f61d6205d8794c7c3bef5afd906b158520fad1b`);
- all three const-reference scalar-operator parameter variants were
  byte-identical (`scalar-operator-parameter-mutations.json`, spec SHA-256
  `9ab3e2c4c13b45c403eccf5d36a4c3a63fd8b6de704b61020f851f83c241f8dc`);
- four named target-creature, reference, and index lifetimes all regressed by
  about 92 to 94 weighted bytes and introduced a reference mismatch
  (`target-creature-lifetime-mutations.json`, spec SHA-256
  `2e767f4b5053e9aee2a3049bd864df08f58edc3f4174eef8bfc1057d2fb0d7c1`).

All 20 planned variants were evaluated. No native-supported improvement
exists in these families, no source change was retained, and final metrics
remain 83.8794233%, a 738.645-byte fuzzy gap, 1,141/1,148 instructions,
prefix 9, and `326/0/0` references. The final eight-record
`experiments.jsonl` SHA-256 is
`7581c8c2d39f5fb69f6971dd4b8f7f1d168603621c64e3d319e03e1e7a3526cb`.

## Component-assignment correction and expanded mutation wave

The same live Binary Ninja target and bundle identify one source-level
imprecision in the recovered target-trail construction. Native computes the
target x delta at `0x0042940f-0x0042941c`, writes it to `var_8.x` at
`0x00429435`, computes the y delta at `0x00429420-0x0042943d`, and writes it
to `var_8.y` at `0x00429457`. This is component assignment into the vector
passed in place to `D3DXVec2Normalize`, not construction of a temporary
vector followed by whole-object assignment.

`direction-pod-storage-mutations.json` tested the recovered assignment shape
independently from the storage type. All seven planned variants were
evaluated. Component assignment is the sole winner, adding
60.573019 weighted bytes and 1.321978 percentage points. Replacing the custom
vector storage with plain `vec2f_t` is byte-identical when combined with that
assignment, so only the source correction is retained. The spec SHA-256 is
`beac4704e5951617e851c50276d3ff3377dfe1e442c6f5a1a71c6886dbe431f5`.

The retained source SHA-256 is
`b4425bd97866530a2a8d39a28925924926010b09a3aa602baee0903e85c84a5b`.
It improves the scratch from 83.8794233% to 85.2014011%, raises the
fuzzy-weighted score from 3,843.355/4,582 to 3,903.928/4,582, and reduces the
gap from 738.645 to 678.072 bytes. Candidate instruction count changes from
1,141 to 1,136 against 1,148 native instructions; prefix remains 9. The
aligned-reference inventory becomes `325/0/0`: one duplicate aligned
reference is folded, with no unresolved or mismatched reference introduced.

The mutation wave added 15 complete records and evaluated 181 planned
variants. The positive assignment record is followed by complete reruns from
the improved source where allocator interactions were plausible:

| family | variants | spec SHA-256 | result |
| --- | ---: | --- | --- |
| tint alpha lifetime | 4 | `76aa7cdffa8e8000d71af5bf297ef126e52fcf479e87fe4c644c570bd83c2aa1` | neutral except one 4.382-byte regression |
| vector scope lifetime | 23 | `e391add15d223cfbd408567e20d0a08fedf76f95944d4f9c7a10552c04b502e3` | effect scope neutral; direction localization regresses |
| disjoint vector storage alias | 2 | `0bb88acdf9e90b9c63b2b2707d47268ced9a915f167acd335eede56349e28d7e` | rejects storage aliasing |
| simple coordinate lifetime | 9 | `a57e8ba4288a55a2503f5c8d2bd46e214ae8d94ab0169eb93ac71237fdb487da` | named centers neutral; explicit forms regress |
| recoil scope, before and after winner | 16 | `3873d9ade93ae5835c618f689a730188497c060e1963fedf689e2d367bdca47a` | all valid variants regress |
| alive tint helper extraction | 5 | `70d78a0ceecc12039fa065acbdc48c10a4d6e5d12f1d45ef0421a27fd9cc8f5a` | value and const-reference helpers byte-identical |
| target stride addressing | 11 | `4cb5fcca6d137391af966a220b47791ad898ca0210f68e547016aa6c1bc96ee0` | `19 * 8` forms neutral; vector subtraction regresses |
| vector operator lowering | 24 | `ec26a9a4593ed06b1e2ebfdfdbdedf473a139dade57c8e64f941a4c1e9f62b54` | canonical forms neutral; explicit assignments regress |
| half-size vector shape, before and after winner | 62 | `3f671eef7fd898bacab7d2585176e4a3f9fd5919a1e2f581c3b38fed44c4397c` | all five-site combinations byte-identical |
| direction storage and assignment | 7 | `beac4704e5951617e851c50276d3ff3377dfe1e442c6f5a1a71c6886dbe431f5` | component assignment retained |
| direction component lifetime | 6 | `38e975f1b69f0d3024f0c7f17c7b557b671d558892b700bd4ba55823730bc23a` | named deltas neutral; reversed order regresses |
| shield and muzzle offset assignment | 8 | `12025e56d6d2f9fdc295bf0390b9e2a29a98688598e3ca488416f5610afdd7d2` | single-site forms neutral; paired forms regress |
| target draw-origin construction | 4 | `c0ec852fd4ca9cb4d2bd38a71f7da7b8dab6828e23f5246cf3638b348b900a21` | all four forms byte-identical |

A separate 30-cell profile matrix covered `msvc6.5` and `msvc6.6` across 15
optimizer flag sets. `/O2 /GB`, `/O2 /G5`, explicit `/Ob1`, explicit `/Ot`,
equivalent `/Og /Oi /Ot /Oy /Ob1|2`, and `/Zp8` all tie the retained
baseline. `/Oi-`, `/Op`, `/Ob0`, `/Os`, and `/O1` regress; `/Za` does not
compile this Windows-backed scratch. No compiler or flag override is retained.

The final 23-record `experiments.jsonl` SHA-256 is
`242ea9b60cec063273c84f1e3e0555beca0e9c3d3d5f377d931dd541cb170e76`.
The first substantive residuals are still reusable-local/x87 scheduling
differences, beginning at native `0x004285e8`; the largest later cluster is
the multiplayer tint schedule at `0x00428c66-0x00428cd2`. The component
correction is therefore retained as semantic recovery, while the remaining
gap stays classified `RESIDUAL=compiler`.

## Alive-torso half-size value shape

The high-weight alive torso region at `0x00428a49..0x00428ad7` exposed one
remaining source-shape difference. Native computes `size * 0.5f` once, keeps
the result on x87, publishes a copy to `[esp+0x34]`, and consumes that same
value for both vector components. The exact neighboring `creature_render_type`
uses the corresponding house style: repeat the half-size expression in both
temporary-vector constructor arguments and let VC6 common-subexpression it.

Applying that shape only to the recoil-adjusted torso position recovers the
native store and raises the whole-function match from `85.2014011%` to
`85.6017505%`. The weighted score gains `18.344014` bytes, from
`3,903.928196/4,582` to `3,922.272210/4,582`, while candidate instructions
move from `1,136` to `1,137` against `1,148` native. Prefix remains 9 and the
reference audit remains clean at `325/0/0`. The retained source SHA-256 is
`fe2a459473a2a397f866a83d91d0eb8eba25be883712c58f22b632bb61c20aed`.

Three bounded controls were rejected: localizing the existing scalar was
byte-identical, publishing components directly through an inlined setter fell
to `84.6221441%` and `320/0/0`, and setting a short-lived vector before copying
it to the shared render vector fell to `84.7368421%` and `320/0/0`. The
repeated component expression is therefore the only measured improvement from
this focused region probe.
