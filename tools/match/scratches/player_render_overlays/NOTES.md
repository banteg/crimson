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
`83.88%` WIP (`1,141/1,148` instructions, prefix `9/1,148`). The target and
candidate prologues are identical through the `sub esp, 0x2c` local-frame
allocation. Masked-reference auditing reports `326/0/0`: every aligned symbol
resolves and agrees without a speculative alias.

The target-trail direction is a two-component value passed in place as both
the destination and immutable source of `vec2_normalize_dispatch`. Its live
prototype is now the proven stdcall
`vec2f_t *(vec2f_t *, const vec2f_t *)`, replacing Binary Ninja's former cdecl
`float *(float *, float *)` guess. Propagating that contract through this
custom vector value is matcher-neutral and leaves the `83.88%` score and
`326/0/0` reference audit unchanged.

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
retained. The two complete records are in `experiments.jsonl`, whose SHA-256
is `e58d5ddfaf83bad77636e03226b2aec95d504fe5ed709f0c06eb2d07595daab3`.
