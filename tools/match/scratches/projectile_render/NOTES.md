# `projectile_render`

Native target: `crimsonland.exe` at `0x00422c70` (12,551-byte manifest
extent).

The recovered callback owns a sequence of separately batched visual passes:
Sharpshooter laser sights, conventional bullet trails, the selected player's
muzzle flash, five plasma-family trail styles, primary projectile sprites and
ion/fire beams, Plague Spreader clouds, Fire Bullets overlays, small projectile
billboards, and three secondary-projectile passes.

The sole native caller pushes `ui_transition_alpha`, calls this function, and
then removes one four-byte argument. The live Binary Ninja database formerly
typed the callback as `void()` and therefore hid that argument in both caller
and callee IL; its saved prototype is now `void(float transition_alpha)`, in
agreement with the recovered source and native stack cleanup.

Live Binary Ninja evidence establishes that plasma trail length converts the
origin-to-position distance and `speed_scale * spacing` to signed integers
before dividing and applying the per-type cap. It does not use the simulation
travel budget. The secondary 140px bloom pass likewise visits every active
secondary entry before the later type-specific sprite and glow passes, so it
also applies to the exploding state. Both findings are recovered in the modern
renderer with focused tests. The later bullet-billboard pass excludes only
Plasma Rifle, Plasma Minigun, and Pulse Gun, preserving a 4px core for
Shrinkifier, Spider Plasma, and Plasma Cannon; that omission is recovered too.

The scratch deliberately retains strict `life_timer == 0.4f` branch tests,
the separate detail-gated passes, the native integer conversions, and the
Plague Spreader's asymmetric trigonometric offsets. Native control flow also
proves that the five plasma styles independently spell out their distance,
trail, head, and aura work. The recovered source now follows the observed
Rifle, Minigun, Cannon, Spider Plasma, Shrinkifier branch order and preserves
Plasma Cannon's asymmetric 3.5 count divisor versus 2.6 step spacing.

The ion/fire family likewise has separate live and fading arms. In particular,
the live arm sets atlas frame (2, 2) before recomputing frame (4, 2), while the
fading arm applies rotation before drawing the trail. The bullet billboard,
secondary sprite, and secondary glow passes use direct per-type draw arms
rather than parameterized sizes and colors. Native disassembly further proves
that the secondary sprite arms are an ordered `1 -> 2 -> 4` comparison chain,
while the detail-glow arms are ordered `4 -> 1 -> 2`; neither pass was a source
`switch`.

The native callback's geometry is built from the game's two-float vector type,
not from independently named scalar coordinates. Live Binary Ninja IL and
disassembly establish the important object lifetimes: all four Sharpshooter
quad points are materialized before the perk gate; each conventional-bullet
type constructs its current point, origin point, half-width, and four output
points within its own branch; and the fading ion-chain arm constructs a
normalized perpendicular, its camera-space endpoints, and four strip points.
After drawing the 10-unit strip, native mutates those same four points by four
more units before drawing the wider 14-unit strip. The secondary bloom and
three glow arms likewise construct camera-space positions by subtracting
direction vectors and scalar half-sizes. Each sprite arm first materializes
`camera + position`, sets its tint, and only then subtracts the half-size in
place. The recovered source now preserves all of those vector operations and
mutations instead of recomputing unrelated scalar expressions.

Those source-shape recoveries raise the honest build from 33.68% to 43.04%.
The candidate now has 2,839 normalized instructions against 3,021 target
instructions, with 325 proven, zero unresolved, and 28 mismatched aligned
references. Treating the adjacent camera coordinates as the aggregate
`camera_offset` object is backed by the native symbol layout and accounts for
the formerly unresolved object-level reference without weakening reference
auditing.

The first residual remains the native 0x19c-byte local frame versus the
candidate's 0x118-byte frame. The remaining 0x84 bytes are concentrated in
other native geometry-temporary lifetimes and allocator scheduling. A natural
beam-direction/base-vector spelling was also tested because the target
materializes adjacent coordinates there, but it regressed global alignment
from 39.77% to 39.08%; the higher-scoring scalar spelling remains semantically
identical and better supported by the current compiler evidence. No dummy
locals, fake references, hard-coded addresses, or artificial register
constraints are retained.

## Binary Ninja type and control-flow recovery

The default analysis-time limit had left this 12,551-byte callback without
LLIL, MLIL, or HLIL. A durable `never_skip` policy now restores 214 basic
blocks. Its six major induction variables are named for the player
aim-heading, conventional-bullet velocity, plasma position, primary origin,
secondary bloom, and secondary sprite passes.

The primary projectile walks now use the existing native cursor-block types
anchored at `vel_y`, `pos_y`, and `origin_y`. This recovers enum `type_id`,
`life_timer`, `speed_scale`, origin, velocity, and tail fields without
pretending that an interior address is a `projectile_t *`. The two secondary
walks analogously use the `pos_y` block, and only fields physically before
their cursor remain negative offsets.

The recovered source now mirrors the three primary cursor lifetimes with
`vel_y`, `pos_y`, and `origin_y` views. In particular, the conventional pass
now emits the native `active - 0x1c`, `type_id + 0x4`, and `life_timer + 0x8`
layout from its induction pointer. The plasma pass also keeps its live
`life_timer == 0.4f` body before the faded arm, matching the direct native
comparison at `0x0042381b` and the fade path beginning at `0x0042407a`.
Direct primary-life comparisons agree with the corresponding
`projectile_origin_y_cursor` branches at `0x004241ae` through `0x004244b5`.

These cursor and branch-layout recoveries raise the callback from 43.04% to
44.84%, reducing the fuzzy gap from 7,149.358 to 6,923.578 bytes. The current
candidate has 2,818 normalized instructions against 3,021 target instructions,
with 358 proven, zero unresolved, and 22 mismatched aligned references. The
native frame remains `0x19c` bytes versus the candidate's honest `0x118` bytes.

## Independent primary projectile arms

Live Binary Ninja disassembly establishes that Pulse repeats rotation and
atlas setup in both of its life arms: the fading arm starts with those calls at
`0x00424284`, rather than inheriting them from above the life comparison.
Ghidra and IDA independently corroborate that ordering.

The same three views show that Splitter and Blade are separate type arms, not a
shared distance-and-clamp body with only their material setup conditionalized.
The Splitter comparison at `0x00424348` enters its own square root, clamp, and
draw path; the Blade comparison at `0x004243d5` enters a second square root,
clamp, and draw path. The source now preserves those independent arms.

These control-flow recoveries raise the callback from 44.84% to 50.96%. The
candidate now has 2,854 normalized instructions against 3,021 target
instructions, with 399 proven, zero unresolved, and 16 mismatched aligned
references. The remaining broad residuals are the already identified geometry
temporary lifetimes and allocator scheduling; the candidate frame is now
`0x120` bytes versus the native `0x19c` bytes.

## Semantic-completion audit

A fresh live Binary Ninja bundle confirms that every native primary and
secondary projectile type arm is present, as are all five direct callees:
`effect_select_texture`, `perk_count_get`, `D3DXVec2Normalize`,
`creature_find_in_radius`, and `__ftol`. Address-matched IDA and Ghidra
snapshots independently report the same `void(float transition_alpha)`
signature and callee set. The candidate has no unresolved static references;
its 16 mismatches are aligned-reference consequences of the remaining
instruction scheduling differences.

An explicit player-pool cursor probe preserved the 2,854-instruction behavior
but regressed the score from 50.96% to 50.28%, increased aligned-reference
mismatches from 16 to 21, and raised the fuzzy gap from 6,154.797 to 6,240.250
bytes. The alternate `msvc6.5pp` profile also regressed to 44.77% with 29
reference mismatches. Together with the previously rejected natural geometry
spellings, this leaves compiler allocation and aligned-reference scheduling,
not missing behavior. The scratch is therefore classified
`semantic-complete` with compiler residuals.

## Compiler-residual source-shape refinement

The first current mismatch remains the prologue: the candidate's honest
`0x120`-byte frame versus the native `0x19c` frame. A 20-profile matrix covered
MSVC 6.0, 6.5, 6.5pp, 6.6, and 7.0 with `/GB`, `/G5`, `/G6`, and `/Oy-`.
Additional VC6.5 probes covered `/Ob0`, `/Ob2`, `/Oi-`, `/Og-`, `/Os`, `/O1`,
and `/GX`. Stock MSVC 6.5 `/O2 /GB` remains best, tied only with equivalent
MSVC 6.6 and `/G5` output; no compiler override is justified.

The native small-billboard pass tests activity and the live `0.4f` lifetime
before loading the projectile type. Delaying the source `type_id` binding until
after those two gates raises the candidate from 50.96% to 51.06%, reduces the
rounded fuzzy gap from 6,155 to 6,142 bytes, and improves the reference audit
from `399/0/16` to `402/0/16`, with the same 2,854/3,021 instructions.

Named initial trail alpha, in-place Sharpshooter start-position mutation, and
separate conventional active/type gates all compiled byte-identically. Moving
the plasma cursor behind its active gate regressed to 50.31% with `384/0/21`
references, while the analogous secondary and Plague gate spellings were
neutral. Only the measured billboard lifetime improvement is retained.

## Reference residual re-audit

A fresh corpus audit keeps the candidate at 51.06%, 2,854/3,021 instructions,
and `402/0/16` references. All 16 mismatches are
aligned mismatches; there are no unresolved references. Live Binary Ninja
confirms `projectile_pool` is a 96-entry, `0x40`-byte-stride array at
`0x004926b8`, with `projectile_pos_y` at `+0x0c`, while `particle_pool` is a
separate typed array at `0x00493eb8`. The mismatch list pairs cursor setup from
different render passes—for example native `projectile_pos_y` against a later
candidate `projectile_pool+0x2c`, and native particle cursors against candidate
projectile cursors. It also pairs differently scheduled x/y camera loads and
constant-pool operations.

Those cross-pass pairs cannot be repaired by changing a field offset or data
alias. Every candidate object resolves, and the shared pool/camera layouts are
already correct. The residual is therefore compiler allocation and instruction
alignment only, and `RESIDUAL=compiler` records that conclusion without hiding
the 16 honest mismatches.

## Recorded localized mutation sweeps

A fresh live Binary Ninja bundle from target
`3023:2:9499448411019345244` has SHA-256
`a395bc39ec795836ea1add24dea60e39dd614f54edbdaa52e121e190f772362a`.
The first mismatch is still the honest `0x120` candidate frame against the
native `0x19c` frame. The first large localized region begins in the
Sharpshooter geometry at `0x00422d63`: the native code keeps the heading,
position, half-width, screen-position, and eight output coordinates live while
also scheduling the perk lookup. Native also tests the conventional projectile
activity byte at `0x00423016` before loading its type at `0x00423021`. These
observations grounded two complete schema-1, single-site mutation sweeps.

The baseline source SHA-256 is
`d0656515e7aefdd6f95fb04d269dc5e903a67d2a386f2609b1df69a1d7676716`:
51.0638298%, 2,854/3,021 instructions, a 6,141.979-byte fuzzy gap, and
`402/0/16` references.

`localized-lifetime-mutations.json` has SHA-256
`87ac8dd5d4accfd1db1a543f09fa42393013c5c121d5dc141cada239122555f4`.
All five possible one-change variants were evaluated:

| rank | variant | source SHA-256 | ratio | fuzzy gap | instructions | refs ok/unresolved/mismatch | result |
| ---: | --- | --- | ---: | ---: | ---: | ---: | --- |
| 1 | `sharpshooter_perk_load_lifetime/count_between_start_and_end_points` | `39b56a82d7ef19d56923c60972d2f8ee7e342cd246f000c1f5ccbd7388004902` | 51.0638298% | 6,141.979 | 2,854 | 402/0/16 | byte-identical |
| 2 | `sharpshooter_perk_load_lifetime/count_after_all_points` | `c0c51dec9cf0fdd6c2f7bf42e4c671781582bb77ac69a5debb9de0236ac3793e` | 51.0638298% | 6,141.979 | 2,854 | 402/0/16 | byte-identical |
| 3 | `secondary_sprite_type_load_lifetime/active_before_type_load` | `94c05ef356999501e07d45fa0da880cbc2735d7bca27e1e17ec514956fb30b81` | 51.0638298% | 6,141.979 | 2,854 | 402/0/16 | byte-identical |
| 4 | `conventional_type_load_lifetime/active_before_type_load` | `5b9a8c431ce01dec3e527242788f0ea8c9d6681a31603f23d1617bf56d04542e` | 51.0638298% | 6,141.979 | 2,854 | 402/0/16 | byte-identical |
| 5 | `sharpshooter_end_position_base/direct_player_position` | `974cd19e5204749aebb6c69fa0cc1956d0fc9977eee39ead18ab722549482e78` | 50.8595745% | 6,167.615 | 2,854 | 398/0/18 | rejected |

`vector-operator-lifetime-mutations.json` has SHA-256
`cc700d94cc6b2a276b52df3d3ccb48b4099b70f08c5431373ba21e4b18cde4ab`.
It tested natural named-result and copy-then-mutate spellings because the native
geometry retains many more value-object temporaries. All eight possible
one-change variants were evaluated:

| rank | variant | source SHA-256 | ratio | fuzzy gap | instructions | refs ok/unresolved/mismatch | result |
| ---: | --- | --- | ---: | ---: | ---: | ---: | --- |
| 1 | `scalar_subtract_result_lifetime/assign_named_result` | `91fb36c5410e16340f0db7eb3f1c3377e3e10f0f20bc2304a2cabab340357ee2` | 51.0638298% | 6,141.979 | 2,854 | 402/0/16 | byte-identical |
| 2 | `vector_scale_result_lifetime/assign_named_result` | `9632f3559c0b6906f77bc5fd7dc1172a8e622713929ccdd39c9584c4876727b1` | 51.0464523% | 6,144.160 | 2,856 | 402/0/16 | rejected |
| 3 | `vector_subtract_result_lifetime/assign_named_result` | `4a0f57f48020f675d874ec991f35619f5253e2f618d866aeab6f234d7810dd6a` | 50.9603944% | 6,154.961 | 2,862 | 399/0/16 | rejected |
| 4 | `vector_add_result_lifetime/assign_named_result` | `b548d228b07937109e26d7b45d50558572377f18df22b444f682d6797885b67b` | 48.2606482% | 6,493.806 | 2,872 | 382/0/19 | rejected |
| 5 | `vector_scale_result_lifetime/copy_then_scale` | `78acec195329b7e31341320b3cbcc3202da71b349ae280928e4802d402deb02b` | 46.7114094% | 6,688.251 | 2,939 | 368/0/17 | rejected |
| 6 | `vector_add_result_lifetime/copy_then_add` | `799c79b5de6cf99fb213467964de0676ea6ad4675127c704ce086138b8a5cc18` | 46.4018614% | 6,727.102 | 2,996 | 368/0/19 | rejected |
| 7 | `vector_subtract_result_lifetime/copy_then_subtract` | `cf9f547930de9ad52780e4c67536f7c0c76e737aabe61faf8a831d71865c22fc` | 45.9346186% | 6,785.746 | 2,944 | 363/0/16 | rejected |
| 8 | `scalar_subtract_result_lifetime/copy_then_subtract` | `d8057ee6d27773793346e4ae0e16c267a51d582d96d27ee491f03f2395413545` | 43.3192210% | 7,114.005 | 2,884 | 351/0/16 | rejected |

No individually positive site exists in either menu, so no interaction was
eligible for testing. Both recorded sweeps report complete one-change coverage,
`best_improves=false`, and zero unevaluated planned combinations. No source
variant was retained, and no recovered runtime-port change is warranted. The
two complete records live in `experiments.jsonl`, whose SHA-256 is
`fde18fafd0338ab823aae8089d96c24dabd7316f6f72cb65632fdb54b7ef8a7a`.

`conventional-assault-geometry-mutations.json` adds a focused two-variant
check of the conventional assault-rifle output geometry. Both natural
alternatives regress by at least 27.66 fuzzy-weighted bytes, with no reference
or prefix gain. No geometry rewrite was retained.

## Cross-pass lifetime follow-up

A fresh live Binary Ninja export from target
`3023:2:9499448411019345244` has HLIL SHA-256
`c1fa9ef04e3aeb54200892374c0593a054f5c748666fadf2a48d0761c0d7fb67`
and disassembly SHA-256
`0dfd7325f582932e85f04935e39a91521b5dc82aeac78781a62cea084ba104a1`.
A focused profile refresh across MSVC 6.5/6.6 and `/GB`/`/G5` reproduces the
same best output in all four cases: `51.0638298%`, 2,854/3,021 instructions,
a `6,141.979`-byte fuzzy gap, and `402/0/16` references. The existing stock
MSVC 6.5 `/O2 /GB` profile therefore remains justified.

Two complete interaction sweeps reject additional cross-pass lifetime
spellings:

- Reusing one function-scope alpha for the pre-pass zero tint and conventional
  projectile life alpha is byte-identical in every valid interaction. The
  seven-variant sweep has spec SHA
  `bb32f4ecf17bcfbd6d2e92081033282e453e5d61acf41f36c9f4c026a877770f`.
- Sharing the four Sharpshooter quad points with the conventional projectile
  pass is also byte-identical when both uses are activated. Merely adding the
  unused function-scope point bank loses `17.09` weighted bytes. The complete
  seven-variant sweep has spec SHA
  `915c76ee9dc101de38b486ca4d25f6bd572bf18f769b38fe3183b7b59269ca41`.

No render source rewrite is retained; its final metrics remain the baseline
above.

## Native clamp branch order

The first coherent residual reference cluster is a real source-order mismatch,
not one of the surrounding cross-pass alignment artifacts. In the live
`crimsonland.exe.bndb`, the plasma fade at `0x0042407a-0x004240a6` multiplies
the life timer by `2.5f`, compares against `1.0f` first, substitutes `1.0f`
when above the upper bound, and only then compares against and substitutes
`0.0f` for the lower bound. The recovered shared clamp helper instead tested
the lower bound first.

The complete three-variant, one-site sweep in
`clamp-order-mutations.json` (SHA-256
`4a640aad4869a9ea82dfef56d142c6d2e08d422c56e5983ebe4e393d9e922db7`)
found that all three upper-first source spellings compile to the same improved
instruction stream. The retained plain upper-then-lower spelling has source
SHA-256
`64b3190b0e76d14d54111c6b32251cad0258aaedc818471afd5bb379dc07c73a`.
It moves the candidate from 51.0638298% to 51.2680851%, adds 25.636
fuzzy-weighted bytes, reduces the gap from 6,141.979 to 6,116.343 bytes, and
changes the reference audit from `402/0/16` to `406/0/12`, without changing
the 2,854/3,021 instruction counts.

The 12 surviving reference mismatches are still isolated alignment pairings.
For example, the audit pairs native camera x at `0x00422e16` with a later
candidate camera y load even though the candidate object contains the proper
x/y relocation sequence. It likewise pairs native `effect_scale * 16.0f` at
`0x004245b8` with a candidate `* 2.5f` from a different block, and pairs the
native 3/4/2-pixel small-billboard branches at
`0x00425561-0x0042561e` with constants from neighboring candidate blocks.
Both the source and the native disassembly confirm those values and field
offsets are already correct. This leaves no second locally coherent reference
cluster to repair honestly.

## Native geometry-lifetime mutation wave

The live `crimsonland.exe.bndb` target
`3023:2:9499448411019345244` exposes two further source-lifetime details. In
the muzzle-flash pass, native materializes the cosine and sine offsets at
`0x0042372b` and `0x00423737`, before the color and batch calls at
`0x0042375a` and `0x00423768`. With two independent scalar locals, MSVC
instead deferred the trigonometry across those calls. The natural
two-component flash vector forces the observed lifetime without changing the
geometry. In the Sharpshooter pass, native finishes the start-screen pair at
`0x00422e12-0x00422e6d` before constructing the end-screen pair at
`0x00422e74-0x00422ee0`; the source now follows that same object order.

Five complete recorded sweeps cover this slice:

- `initial-alpha-lifetime-mutations.json` (SHA-256
  `3638714e584f47019e522420fbceb5751ca6d8dfbabb32f50b8450c671dfbd81`)
  evaluates all three named-alpha variants. All are byte-identical, so the
  scalar spelling cannot explain the native pre-pass stores.
- `conventional-base-lifetime-mutations.json` (SHA-256
  `2a633f74b2664dff318ca0dc2b312fe912e9df0ec0cefaef2adea3faf964c966`)
  evaluates all 107 one- through four-site variants. Every one-site variant
  regresses by 17.991 to 46.847 weighted bytes. A four-site interaction gains
  5.706 bytes only on the old baseline, drops 13 candidate instructions, and
  ceases to improve after the independently supported muzzle change. It is
  rejected as an alignment interaction.
- `sharpshooter-screen-lifetime-mutations.json` (SHA-256
  `ce6012511969a9629892dbad8c2527c2b52e5deda3f35cdc136eb5626f54f13a`)
  evaluates all three screen-base spellings. The native sequential ordering
  is the only improving variant.
- `muzzle-flash-vector-lifetime-mutations.json` (SHA-256
  `4952c24be5f13c385ab8f7648d2429ff19d9eccc1be253f6c5f90712a48ecde9`)
  evaluates all three aggregate spellings. The constructed and member-assigned
  vectors tie at +10.624 weighted bytes; the simpler constructor is retained.
- `native-base-order-interactions.json` (SHA-256
  `f3f457a75b21636b3becc97eb1e7c00f7c65c1b50476d176636479894df440e1`)
  evaluates all 31 interactions on the improved muzzle baseline. Only the
  single Sharpshooter ordering improves, by another 6.467 weighted bytes; all
  conventional combinations regress and remain rejected.

The retained source SHA-256 is
`70f2cd4d66e04eb6c7d35eb725d462ebc86604af832d2038cf762b1c7dbadab2`.
It raises the candidate from 51.2680851% to 51.4042553%, adds 17.091
fuzzy-weighted bytes, and reduces the gap from 6,116.343 to 6,099.252 bytes.
The final candidate remains 2,854/3,021 instructions. Its audit is
`407/0/13`: all 13 residuals are aligned mismatches and there are still no
unresolved references. The two extra Sharpshooter pairings are the expected
alignment cost of the native-evidenced object order, while the higher-priority
byte score improves. `crimson match validate` accepts the retained source, and
the complete records are appended to `experiments.jsonl`.

## Ion and secondary-projectile native-lifetime wave

The fresh Binary Ninja bundle from target
`3023:2:9499448411019345244` is saved as
`/tmp/wave6-projectile-render-bn-bundle.json` with SHA-256
`a395bc39ec795836ea1add24dea60e39dd614f54edbdaa52e121e190f772362a`.
It resolves four additional lifetime and construction-order details:

- The live ion head reloads the projectile type at `0x00424562`, after the
  normalization call, rather than preserving the earlier cached type.
- The fading ion trail reloads the type for its color arm at `0x004249b2`.
  The other apparent reload sites at `0x00424684` and `0x0042489a` do not
  compose positively with those two sites and are not retained.
- After normalizing the ion arc at `0x00424bfb`, native rotates that same
  vector perpendicular in place at `0x00424c00-0x00424c12`. It constructs the
  projectile-space start at `0x00424c16-0x00424c58`, scales the perpendicular,
  emits the first two strip points, and only then constructs the creature-space
  end at `0x00424cee-0x00424d2e`. The source now preserves that order.
- The secondary main-sprite pass tests the live exploding type at
  `0x00425869`, calls `grim_set_rotation` at
  `0x00425872-0x0042587e`, and reloads the type at `0x00425884` before its
  ordered `1`, `2`, and `4` draw arms. The source now has the same lifetime.

The first three changes were selected by the complete 15-variant interaction
sweep in `native-reload-arc-interactions.json` (SHA-256
`f5b8794a4e3796e147935dfe7d3943639e36c4b19b2a069b16d4941228ed1c0d`).
Together they add 20.262 fuzzy-weighted bytes. The complete three-variant
`secondary-bloom-type-lifetime-mutations.json` sweep (SHA-256
`cfeda77185cd88b8db3b01a81855f6a4d6cc04e5dc5a3e80ea160807535a5483`)
then finds all three reload spellings byte-identical at another +15.984 bytes;
the direct gate followed by the post-call reload is retained because it is the
smallest spelling of the observed native order.

The wave also records useful negative evidence:

- `ion-arc-sequencing-mutations.json` and
  `ion-arc-native-operator-mutations.json` cover 24 and 14 variants,
  respectively. Their isolated winners were superseded by the complete
  interaction result above.
- `ion-type-reload-mutations.json` records both a 25-variant bounded pass and
  all 31 possible interactions. `ion-remaining-type-reloads.json` covers the
  seven remaining combinations; none improves the retained baseline.
- A direct primary-life reload gains 4.273 bytes alone, but loses 26.730 bytes
  when composed with the retained native ion shape, so it is rejected.
- The full 80-variant, one- through four-site interaction sweep of
  `vector-operator-lifetime-mutations.json` contains no improvement.
- The fire-overlay position, billboard type-reload, and secondary main
  draw-position sweeps cover 3, 11, and 4 variants. Aggregate fire geometry
  loses at least 767.6 bytes, billboard reloads lose at least 22.46 bytes, and
  the natural secondary component spellings are neutral or regress. A
  position-cursor spelling compiles byte-identically. None is retained.

Against source SHA-256
`70f2cd4d66e04eb6c7d35eb725d462ebc86604af832d2038cf762b1c7dbadab2`,
the retained source SHA-256
`42ab3c4c4db525b99d67b1528fb8ab91d898bf3bcd42f6194fd20fe2e62602f8`
moves the ratio from 51.4042553% to 51.6930407%, adds 36.245
fuzzy-weighted bytes, and reduces the gap from 6,099.252 to 6,063.006 bytes.
The candidate grows from 2,854 to 2,856 instructions against 3,021 native
instructions. References remain `407/0/13`, so the improvement does not trade
bytes for reference debt. Thirteen complete mutation records were appended in
this wave; `experiments.jsonl` now has SHA-256
`0ccae8857489a84d963e55b7183efbf526dd622a5aa17fd7c53f507e127ac70d`.

## Plasma segment-index x87 lifetime wave

The five plasma arms share one further native compiler shape. In each inner
segment loop, the target converts the loop index once and keeps that x87 value
live across the first product: `fild; fld st(0); fmul step_y; ...; fmul
step_x`. The previous source converted the index independently in both
coordinate expressions, producing an extra load and pop in every loop.

Three complete sweeps bound the repair:

- `plasma-segment-product-order-mutations.json` (SHA-256
  `89eac8a5a63d6e17abf1fe6a9e164b588eec2bbe2f0d09592c790a174aecb948`)
  evaluates all 55 one- and two-site X/Y product-order variants. Every variant
  is byte-identical, ruling out commutation as the cause.
- `plasma-rifle-segment-lifetime-mutations.json` (SHA-256
  `711b09b390d1c18ccc4b5e3e3a2dba847bb6b747c5836119d10e344477df11da`)
  evaluates all four bounded lifetime spellings in the rifle arm. A named
  converted index is the only winner, adding 6.481 fuzzy-weighted bytes and
  removing the exact two extra candidate instructions without changing
  references.
- `plasma-segment-index-lifetime-interactions.json` (SHA-256
  `576da6b4236c4959c71ce68b04bc97cb2ab5ca1058ca12828fc826667b96470b`)
  evaluates all 31 non-empty combinations across the five arms. Every site is
  independently additive; retaining all five adds 32.451 fuzzy-weighted bytes
  and removes ten extra instructions.

The retained source SHA-256 is
`806090184581b0b999df3214fc8899085410b584afcd826434e2c51a7980b71d`.
It moves the ratio from 51.6930407% to 51.9515937%, raises the weighted match
from 6,487.994 to 6,520.445 bytes, and reduces the gap from 6,063.006 to
6,030.555 bytes. The candidate is now 2,846/3,021 instructions. That global
count moves farther from the target, but each changed local loop loses exactly
the two candidate-only x87 instructions and reproduces the native schedule.
References remain `407/0/13`.

`crimson match validate` accepts the source, the normalized candidate and
target dumps confirm the local schedule, and the 511-variant experiment audit
has no errors. The three complete records bring `experiments.jsonl` to 28
records with SHA-256
`59a6478a0f7c6dc4659787e2a3aa4fc7d68f2ccf6d2bcd5e221c1e035558f865`.

## Plasma distance x87 lifetime and branch-shape wave

The five plasma render arms use two distinct native distance schedules. Plasma
Rifle and Plasma Minigun keep a named scalar `sqrt` result live until the
integer conversion. Plasma Cannon, Spider Plasma, and Shrinkifier instead
construct a two-component difference and invoke its inlined `length()` method,
which produces a different x87 multiply/add stack order.

Six complete sweeps bound the recovery:

- `plasma-rifle-distance-conversion-lifetime-mutations.json` (SHA-256
  `1cce64a09eadffa89fc078c003b7b4573bf0418d5087999c0599a2fa8f89449c`)
  evaluates 12 scalar conversion lifetimes. The named `float distance` is the
  only local shape that reproduces the Rifle schedule.
- `plasma-distance-conversion-lifetime-interactions.json` (SHA-256
  `5b5b09daa6073141df903606fbdce2fa3aaf3f3a01769c0b200d51c80a8320cb`)
  evaluates all 31 non-empty combinations across the five arms. It confirms
  the same scalar lifetime for Minigun, while the aggregate all-five score is
  rejected because Cannon, Spider, and Shrinkifier retain the wrong native x87
  order.
- `plasma-cannon-distance-product-lifetime-mutations.json` (SHA-256
  `3ce3903d3f2eec85bf29448c1a2b37a3ed6544d78db4c213590bd93300339cf2`)
  evaluates 15 product and vector spellings. A temporary two-component vector
  followed by `length()` exactly reproduces the Cannon kernel and adds one
  proven reference.
- `plasma-vector-distance-lifetime-interactions.json` (SHA-256
  `fbd66670edc161cd0d664b997877b2e426769bfadc76bc39692620f442469f76`)
  evaluates all seven non-empty Cannon/Spider/Shrinkifier combinations. Cannon
  plus Spider is the honest winner; applying the same spelling to a catch-all
  final `else` lets VC6 hoist shared coordinate differences across the Spider
  gate, unlike native.
- `plasma-tail-vector-distance-shapes.json` (SHA-256
  `4b35537e3da5815f2b7dccbe751127211daf4eceb34c80201db0a8b05666419b`)
  evaluates all 48 one- and two-site Spider/Shrinkifier vector shapes. Its
  aggregate score winner emits extra temporary stores and does not reproduce
  the local target, so it is retained only as negative evidence.
- `plasma-shrinkifier-distance-shape-mutations.json` (SHA-256
  `d95b20502f3c747dbd3ab11f7d429a8445a4e3ec49771414377a7a0c2fe8f7e6`)
  evaluates ten final-arm branch and vector shapes. An explicit
  `PROJECTILE_TYPE_SHRINKIFIER` condition plus the temporary vector `length()`
  is the top result, adding 24.271 fuzzy-weighted bytes, five instructions
  toward native, and one proven reference. The same vector expression under a
  catch-all `else` regresses, isolating the final type gate as the compiler
  constraint that prevents cross-branch common-subexpression elimination.

The normalized target and candidate dumps now agree instruction-for-instruction
through all five distance kernels. In particular, Spider and Shrinkifier each
retain their own `cmp` gate, coordinate loads, `fsub` pair, vector
multiply/add stack, `fxch; fsqrt; fxch; fstp`, and conversion call.

Against source SHA-256
`806090184581b0b999df3214fc8899085410b584afcd826434e2c51a7980b71d`,
the retained source SHA-256
`5c2edb8b2f6dfc4322c49e17778d3a7d37077a231a02b98e7787769fdeaa4edb`
moves the ratio from 51.9515937% to 52.7031622%, raises the weighted match
from 6,520.445 to 6,614.774 bytes, and reduces the gap from 6,030.555 to
5,936.226 bytes. The candidate moves from 2,846 to 2,861 instructions against
3,021 native instructions. References improve from `407/0/13` to `412/0/13`.

`crimson match validate` accepts the retained source, and the 634-variant
experiment audit has no errors. The six complete records bring
`experiments.jsonl` to 34 records with SHA-256
`3dc768269aa02cad61a66363983a744c6cc7672aa9c3f2b8d469a5f95e7d6a37`.

## Primary displacement-distance semantic and lifetime wave

The live native primary-projectile pass exposed a semantic recovery error in
three adjacent branches. Pulse Gun at `0x004241b4`, Splitter Gun at
`0x0042435e`, and Blade Gun at `0x004243eb` all subtract current position from
origin position before measuring their billboard size. The previous source
measured velocity magnitude instead. Each native branch also uses the same
inlined two-component `length()` x87 kernel recovered for the Plasma Cannon:
load and subtract both components, square the first while preserving the
second, square the second, add, and take the square root.

The complete 124-variant, one- through three-site sweep in
`primary-displacement-distance-shapes.json` (SHA-256
`0fde46a672e42e4db6a557b79974531c7466b55c8b97f64de05a22a655b8e291`)
bounds four scalar and vector spellings at each site. Every isolated semantic
repair regresses the global alignment score, but the three recovered
lifetimes compose positively. All combinations of the temporary and named
vector spellings at all three sites compile identically and tie for first.
The simpler temporary-vector spelling is retained.

The normalized candidate dump now reproduces the target displacement loads,
subtractions, x87 product order, square root, and Pulse scale multiply. The
three-site interaction adds nine candidate instructions toward native, raises
the weighted match by 15.461 bytes, reduces the gap from 5,936.226 to
5,920.765 bytes, and moves the ratio from 52.7031622% to 52.8263453%.
References improve from `412/0/13` to `413/0/11`, and the candidate is now
2,870/3,021 instructions.

The retained source has SHA-256
`d0eb9aa6d486f01aa014963b314d6d7cbff4bb490bbd2cd3a082b8e628bd8a09`.
`crimson match validate` accepts it, and the experiment audit reports zero
errors across 35 complete sweeps and 758 variants. `experiments.jsonl` now has
SHA-256
`77c1af0215d8a780900ddaa46c55f7a0f9edd2d606966ce2d4ac526f73c28239`.

## Plague timer source, order, and rounding-lifetime wave

The native plague pass begins at `0x00424fd2`, immediately after the preceding
`grim_end_batch`. It loads address `0x00487060` with signed `fild dword`,
multiplies first by `0.001f` and then by `9.0f`, and keeps that x87 value live
while constructing the first `grim_set_config_var` call. Binary Ninja names
the address `survival_elapsed_ms`; the previous recovery instead read the
unsigned `highscore_active_record.survival_elapsed_ms` field after all three
batch-setup calls. VC6 therefore emitted an unsigned qword-conversion
temporary, the wrong source order, and a folded `0.009f` constant.

Two complete five-variant sweeps bound the repair:

- `plague-phase-source-order-mutations.json` (SHA-256
  `6ee8a3e91c94fb08f69a0a3c0c0ec6e84a32dc1525af8c594d307752c4b27fe5`)
  varies the signed source and its position around the batch setup. Only the
  signed dword forms placed before the calls reproduce the native load and
  scheduling; the standalone global and an explicit signed field cast compile
  identically. The global spelling is retained because it is also the native
  symbol at `0x00487060`.
- `plague-phase-lifetime-mutations.json` (SHA-256
  `df3feca9c7e723055ab747e20d10cfc016615adbc5493aa170f78459eef6ecf1`)
  varies five ways of preserving the intermediate `elapsed * 0.001f` result.
  All five compile identically and improve without tradeoffs. The minimal
  parenthesized chain is retained; unlike the ungrouped expression, VC6 keeps
  the native two-`fmul` rounding boundary instead of folding the constants.

The retained object now matches the native island instruction-for-instruction
apart from the function-wide stack-slot displacement: `fild dword
[_survival_elapsed_ms]`, the two `fmul` relocations, interleaved first-call
construction, and final `fstp`. Against the prior source, the two sweeps add
24.694 fuzzy-weighted bytes, reduce the gap from 5,920.765 to 5,896.071 bytes,
and move the ratio from 52.8263453% to 53.0230978%. References improve from
`413/0/11` to `415/0/11`. The candidate is now 2,867/3,021 instructions; the
lower aggregate instruction count comes from removing the non-native unsigned
qword conversion sequence.

The retained source has SHA-256
`7a5f066a76e108429ac840e040fdf1589652b96d2c348ca0161392a602e01318`.
`crimson match validate` accepts it, and the experiment audit reports zero
errors across 37 complete sweeps and 768 variants. `experiments.jsonl` now has
SHA-256
`6cd9a11ce8e873d962c98796bd4e7482879d4b3522e6e137bc7720cb2de95e52`.

## Primary type alias and Plague life-branch wave

The native primary-projectile walk does not preserve one scalar type value
through all of its Pulse, Splitter, Blade, ion, and Fire Bullets arms. It
repeatedly reads the live `type_id` field from the induction record. The
previous source copied that field into a value local, which let VC6 keep the
copy in a callee-saved register through the entire iteration and displaced
the native cursor, creature-index, and transition-alpha register owners.

The complete four-variant
`primary-type-alias-lifetime-mutations.json` sweep (SHA-256
`85f05d87f1e3c530d9592f881d36162cea73e2abd6ada307732c0ea6c7b79b17`)
tests mutable, const, right-const, and volatile C++ reference aliases. The
three nonvolatile forms compile identically: VC6 now reloads the field at the
native decision points, adds nine proven references, and gains 152.320
fuzzy-weighted bytes. The mutable reference is retained because it honestly
models an alias to the mutable record field. The volatile form scores another
24.433 bytes by forcing thirteen extra instructions, but neither the binary
nor the game semantics support volatile storage, so that higher-scoring
fakematch is explicitly rejected.

Two bounded Plague sweeps close the adjacent life branch:

- `plague-life-condition-lifetime-mutations.json` (SHA-256
  `ce0e4a0aef7c41efdd093594e022ca07a4d52bbabee4eab013eb7bb6acf923d7`)
  covers all five condition/reload combinations. Reloading
  `life_timer` directly in the fade arm is the only positive retained
  lifetime, adding 4.263 weighted bytes. It lets the comparison consume its
  x87 value and makes the fade path reload the field at candidate offset
  `0x233c`, matching native `0x0042523c`. The condition-only dependent
  mutation intentionally fails to compile because it removes the value still
  used by the unchanged fade arm; every planned combination was nevertheless
  evaluated and recorded.
- `plague-life-condition-source-shapes.json` (SHA-256
  `8d05f8491c297347dc35ed0f9964aa8d0caf0f8d734f14c22160f399c13aa734`)
  covers six float and raw-bit comparison spellings after the primary alias
  repair. Named raw-bit comparisons score 4.263 bytes higher but require
  unjustified type-punning. The retained direct float-field comparison is the
  best natural source form and still gains 3.472 bytes. VC6 now emits an
  integer field comparison, with the constant hoisted into `ebp`; native uses
  the same bit comparison as an immediate at `0x0042504f`. The remaining
  register difference is therefore isolated to the broader primary-loop
  allocation rather than the Plague condition semantics.

Against the prior source, this wave raises the weighted match from 6,654.929
to 6,814.984 bytes, reduces the gap from 5,896.071 to 5,736.016 bytes, and
moves the ratio from 53.0230978% to 54.2983350%. The candidate is now
2,865/3,021 instructions. Proven references rise from 415 to 424 with none
unresolved. The mismatch counter moves from 11 to 12 because the new global
alignment pairs both correct candidate `4.0f` ion-widen constants against the
earlier native `10.0f` strip constants at `0x00424c71` and `0x00424c7e`;
the source contains both native constants, so this is an exposed alignment
residual rather than a new wrong data reference.

The retained source has SHA-256
`f1d546c79eab8d85211421b597dd8c5ad030ae86c740b0f5c05aa87bf8b72826`.
`crimson match validate` accepts it, and the experiment-ledger check reports
no malformed records across 40 complete sweeps and 783 evaluated variants.
`experiments.jsonl` now has SHA-256
`755cb9bbbf197e5d6b4bc5e0a2ba7810728a554d88a503f31e7113cc9100eda9`.

## Plasma type-alias lifetime wave

Two complete bounded sweeps test whether the primary type-field recovery
generalizes to the remaining projectile passes:

- `primary-life-alias-lifetime-mutations.json` (SHA-256
  `3ba37b42fd5fdbb8e007c9ea236581292c73f1bcbba806f489499164f69ab254`)
  tests mutable, const, right-const, and volatile aliases for the primary
  `life_timer`. All four spellings compile identically, remove two candidate
  instructions and two reference mismatches, but lose 1.950 fuzzy-weighted
  bytes. The value lifetime is therefore retained: the lower mismatch count
  is an alignment side effect, not sufficient evidence for a source change.
- `render-type-alias-lifetime-interactions.json` (SHA-256
  `d3d7ae5bd04e2ce311ea81961367c0f7c9be0058d62acef85ec5cbfcbb75be68`)
  exhausts all 31 nonempty combinations of reference aliases in the
  conventional, plasma, billboard, secondary-sprite, and secondary-glow
  loops. Plasma alone is the only positive variant without a tradeoff: it
  gains 4.265 weighted bytes with identical instruction and reference counts.
  Billboard alone and billboard plus plasma score 24.426 and 28.690 bytes
  higher, respectively, but each loses seven proven references and adds four
  mismatches. Those higher aggregate scores are rejected. The conventional
  and both secondary aliases regress independently.

The retained plasma reference models repeated reads from the live mutable
record rather than a copied scalar. It raises the weighted match from
6,814.984 to 6,819.249 bytes, reduces the gap from 5,736.016 to 5,731.751
bytes, and moves the ratio from 54.2983350% to 54.3323140%. The candidate
remains 2,865/3,021 instructions with references unchanged at `424/0/12`.

The retained source has SHA-256
`63d0bbbce7a45ed03be5b9615764d9ba9cc65fd3b0f5498cda74be6ac8ea6afd`.
The two complete records bring `experiments.jsonl` to 42 sweeps and 818
evaluated variants with SHA-256
`ae60fd2af8b5b2c6f6951a4d44f2683be56dbf988be5bcb98fdedade92f46098`.

## Ion arc result-ownership wave

Fresh inspection of the largest remaining ion-chain region identifies real
vector result boundaries that the previous compact source had elided. Native
computes the creature-minus-projectile displacement at
`0x00424bcc-0x00424bee` into one pair of stack slots, copies that pair into the
vector normalized at `0x00424bfb`, and preserves the normalized vector while
rotating it perpendicular in place. Native likewise materializes the
camera-plus-projectile and camera-plus-creature results before fanning each
result into the two strip points. The later four-unit widening pass recomputes
`arc * effect_scale * 4.0f`, rather than multiplying the already named side
vector.

Three complete bounded sweeps recover and bound those ownership details:

- `ion-arc-copy-boundary-mutations.json` (SHA-256
  `65c38663c78f86fb5b267e18f0deae301fb7368f2c88a5a849d5ae01c4292605`)
  exhausts all 66 single- and two-site combinations across copy assignment,
  arc, start, and end result boundaries. Named arc and end results are the
  clean winner, adding 100.002 weighted bytes while removing two aligned
  reference mismatches.
- `ion-arc-strip-copy-refinement-mutations.json` (SHA-256
  `d3468b02c39b69537941f36590316ae52448f57ea776dc57ccb88f17cde0fa59`)
  exhausts all 132 single- and two-site combinations across the remaining
  start, side, strip, and widen boundaries. A named start result copied by
  members, together with the native recomputed widen chain, adds another
  14.251 weighted bytes and five proven references. Direct copy-then-mutate
  strip spellings do not improve and remain rejected.
- `vector-copy-constructor-mutations.json` (SHA-256
  `7a2740f07b7804590ec312658dd3428f131809a2ca18cb5aa28f9b952b8519e6`)
  tests all four natural x/y construction orders. Every user-defined copy
  constructor loses 148.716 to 159.540 weighted bytes, drops four proven
  references, and adds a mismatch. The vector therefore keeps its implicit
  copy constructor; the recovered boundaries are local expression ownership,
  not a function-wide type property.

Together the retained changes raise the weighted match from 6,819.249 to
6,933.501 bytes, reduce the gap from 5,731.751 to 5,617.499 bytes, and move
the ratio from 54.3323140% to 55.2426196%. The candidate grows from 2,865 to
2,873 instructions against 3,021 native instructions. References improve from
`424/0/12` to `430/0/10`, with no unresolved references or new reference
debt.

The retained source has SHA-256
`cb9e5d01f55b3f2c4fc4b59cd0b81c0cc7eb5472268575780d49860609c1458f`.
The three complete records bring `experiments.jsonl` to 45 sweeps and 1,020
evaluated variants with SHA-256
`64d26eddafd5d0ea28f41df03ec4344577ae245e7faa8cfd61991167bf5d7fd6`.

## Ion direction-result ownership wave

The live and fading ion arms contain the same higher-level ownership boundary
as the recovered chain arc. At `0x00424500-0x0042455d` and
`0x00424838-0x00424895`, native computes the unnormalized two-component
displacement into one pair of locals, calculates its length from that pair,
copies both components into a second vector, and normalizes the copy. The
previous source wrote the displacement directly into the normalized vector,
erasing the result object and its copy boundary.

`ion-direction-result-ownership-mutations.json` (SHA-256
`ecfca2b793c87910cd926766f6832e5062d4926c084bf37b16e7acf50480e6d1`)
exhausts all 24 single- and two-arm combinations across constructor,
subtraction, assigned-member, aggregate-copy, and member-copy spellings. The
corrected complete sweep has no compile errors. A preliminary run exposed an
invalid exploratory union-member spelling; the spec was corrected and the
entire matrix rerun before retention.

The live constructor result followed by an aggregate copy and the fading
constructor result followed by a member copy are the clean winner. Several
fading result spellings compile identically on the winning live baseline; the
member copy is retained because it expresses the observed two-object boundary
without an extra type-punning subtraction expression.

The retained source adds 236.069 fuzzy-weighted bytes, reduces the gap from
5,617.499 to 5,381.430 bytes, and moves the ratio from 55.2426196% to
57.1234965%. The candidate grows from 2,873 to 2,882 instructions against
3,021 native instructions. Proven references rise from 430 to 442 while the
audit remains `442/0/10`, so the improvement adds neither unresolved
references nor mismatch debt.

The retained source has SHA-256
`d2c1d9ab1fb31dac509e2c082c7a9ab8cb8661a171f1db7f7c0dac12bd6d3c72`.
The two records bring `experiments.jsonl` to 47 sweeps and 1,068 evaluated
variants with SHA-256
`269cec72f2a3f5c8fd2c9769f4a600110ba269ab939f974f75f14d92075b2ac6`.

## Conventional projectile result-ownership wave

The four conventional trail arms expose the same missing expression-result
boundary as the ion paths. In the Assault Rifle and catch-all arms, native
finishes the camera-plus-current result and its first two strip points before
materializing the camera-plus-origin result and the final two points. The
Pistol and Gauss arms preserve both results across their four point
calculations. The previous source collapsed each camera addition directly
into its long-lived vector and obscured both the result copy and the native
branch-local ordering.

`conventional-result-ownership-mutations.json` (SHA-256
`8fd4eda06fb7c654bad33b69605df530befa0456eb9f4631ab80ff40a819f819`)
tests aggregate copies, member copies, and sequential result lifetimes at all
four arms. A 66-variant single- and two-site pilot first found the sequential
Assault and catch-all ownership pattern. The subsequent exhaustive run
evaluates all 255 nonempty combinations, including every three- and four-site
interaction.

The retained winner uses an explicit member copy for the Assault result,
aggregate result copies for Pistol and Gauss, and sequential aggregate result
copies for the catch-all arm. It adds 34.649 fuzzy-weighted bytes without
changing the `442/0/10` reference audit. VC6 emits four fewer instructions,
moving the aggregate instruction count from 2,882 to 2,878 against 3,021
native instructions; that count-distance tradeoff is recorded rather than
hidden. The local alignment improvement and native-supported ownership and
ordering are the retention evidence.

The weighted match rises from 7,169.570 to 7,204.219 bytes, the gap falls from
5,381.430 to 5,346.781 bytes, and the ratio moves from 57.1234965% to
57.3995592%. The retained source has SHA-256
`608898f73842f070a152fe47fd0595aa9b0f6eec8bcaf4e36ed086338026091c`.
The two complete records bring `experiments.jsonl` to 49 sweeps and 1,389
evaluated variants with SHA-256
`d3bcbf9797ae8eb5d76d9d0655ed859b3005f2ba09c7324960afe5acf197f176`.

## Sharpshooter result-ownership wave

The opening Sharpshooter sight remains the largest localized mismatch region.
Live native disassembly shows the player position copied at
`0x00422d6b-0x00422d7b`, the end and start rays built at
`0x00422d7f-0x00422df5`, the half-width at
`0x00422df7-0x00422e0b`, and the sequential start/end screen results and four
quad points at `0x00422e12-0x00422ee0`. The perk gate and draw then consume
those points at `0x00422ee7-0x00422f55`.

`sharpshooter-result-ownership-mutations.json` (SHA-256
`a068cc073d49e7a54f08bb0977a3e60f9f46a1731f31199dd4b85ef765c1b2d2`)
tests default assignment, aggregate result copies, and member result copies at
all seven outer vector boundaries. The exhaustive run evaluates all 210
single- and two-site variants. Only the camera-plus-end result copied into the
long-lived end screen by members improves. Every two-site tie is that winner
plus a byte-neutral spelling, so no unsupported interaction is retained.

The exact recovered `vec2_sub` and `vec2_add_out` functions confirm the game's
member-style destination ABI, but the Sharpshooter operators are inlined.
`sharpshooter-direction-lifetime-mutations.json` (SHA-256
`5f7e7c5e4cfc53b2b9d756a345fb1881771059b4979e2c4d5bbadb84bd9e5869`)
therefore bounds the remaining inner constructor/scale hypothesis without
changing that ABI globally. It exhausts all 63 single-, double-, and
triple-site combinations across the end ray, start ray, and half-width
direction. Named unit and scaled directions compile byte-identically; direct
half-width component spellings do not improve. No change from that falsified
matrix is retained.

The retained member copy adds 4.255 fuzzy-weighted bytes with identical
2,878/3,021 instruction and `442/0/10` reference counts. The weighted match
rises from 7,204.219 to 7,208.474 bytes, the gap falls from 5,346.781 to
5,342.526 bytes, and the ratio moves from 57.3995592% to 57.4334633%.
The retained source has SHA-256
`9105e341ecc8832b1afa55b9afbe64c631b760bb4ce49b97b5bafad1733aadaa`.
The two complete records bring `experiments.jsonl` to 51 sweeps and 1,662
evaluated variants with zero malformed records and SHA-256
`ccea677de13bc41e6787015957bd51949c4e0bd6ec2f084848f8d9cc8d675786`.

## Conventional width-result ownership boundary

`conventional-width-result-ownership-mutations.json` (SHA-256
`7a11c97dfe7e51eb0b8394e23a6463521f1a4d98540932f346aec5f8ef55924b`)
tests all fifteen single-site result-copy spellings at the pistol, Gauss, and
remaining conventional-projectile width calculations. Default assignment,
aggregate-result assignment, and an assigned aggregate result are
byte-identical at every site. Member and reverse-member copies consistently
regress by 350.097 fuzzy-weighted bytes, add one candidate instruction, and
lose 23 resolved references without fixing a mismatch.

No source change is retained. The scratch remains at 57.4334633%,
2,878/3,021 instructions, and `442/0/10` references. The complete record brings
`experiments.jsonl` to 52 sweeps and 1,677 evaluated variants with SHA-256
`05cfef9a2396ffc6b12ad05a4fa9027061b403fa5d0885277a96e278ba4096d6`.

## Plague heading operand order

The original SDK and native renderer agree on a narrower source-style rule:
coordinate arithmetic is written in the order it is conceptually assembled,
and VC6 preserves that left-associative x87 lifetime. In the Plague Spreader
heading quad, native `0x004250b7..0x0042510d` computes the centered
camera-plus-projectile base first and adds the sine or cosine displacement
afterward. The previous source added the displacement before subtracting the
30-pixel half-size.

Writing each coordinate as `camera + position - 30 + displacement` reproduces
the native base-first `fld`/`fadd`/`fsub` followed by `faddp` schedule. A named
aggregate position instead regresses, so this is an operand-order recovery,
not a general request for more vector temporaries. The change adds 10.318
fuzzy-weighted bytes, raises the ratio from 57.4334633% to 57.5156753%, and
improves the reference audit from `442/0/10` to `444/0/10`. Candidate
instructions move from 2,878 to 2,880 against 3,021 native instructions.

The retained source has SHA-256
`064300adaa4c79f175dd6e578dfe7fce3088c16a92474b63e78b85b2b70296fc`.

## Ion strip atlas coordinate

The highest-weight residual region begins with the ion-chain strip UV setup.
Native `0x00424b5c..0x00424bb8` pushes `0x3f200000` for the U coordinate at
all four vertices, proving `0.625f`; the previous source used the nearby but
incorrect decimal `0.6f` (`0x3f19999a`). The atlas-coordinate correction is
semantic and leaves the already-recovered vector and loop ownership intact.

The change adds 17.015 fuzzy-weighted bytes, raises the ratio from
57.5156753% to 57.6512456%, and keeps the candidate at 2,880/3,021
instructions with the same `444/0/10` reference audit. The retained source has
SHA-256
`68913092f7709a0627a0ee1500d01851f3ad959dc227de8d4c7fbc0610ca61bb`.

## Conventional type refresh boundary

The next-largest non-ion region covers the Gauss and catch-all conventional
trail arms. Native confirms their semantic constants and branch order already
match the source: Gauss uses `1.1f`, the catch-all uses `0.7f`, and the Gauss
arm precedes the final catch-all. The missing boundary is earlier: after both
trail-alpha `grim_set_color_slot` callbacks, native reloads the live projectile
type at `0x004230d9` before selecting the four geometry arms. The previous
source preserved the pre-callback value through those calls.

Refreshing `type_id` from `tail->type_id` at that point also lets VC6 keep the
initial gate value in `EAX`; its known-zero arm naturally emits native
`mov [active], al` at `0x00423036`. Spelling that source assignment as either
`0` or `type_id` is byte-identical, so the ordinary zero assignment remains.

The refresh adds 37.052 fuzzy-weighted bytes, raises the ratio from
57.6512456% to 57.9464588%, and moves the candidate from 2,880 to 2,881
instructions against 3,021 native instructions. References remain
`444/0/10`. The retained source has SHA-256
`37901a9c83fd5fec5cd53cd03f6b8fa7967c77e9deaccfda966bd7fd5a27459d`.

## Muzzle-flash post-callback player reload

The next independent high-weight island is the muzzle-flash draw at
`0x004236d7..0x004237c2`. Native uses the first indexed player address for the
alpha, heading, and color setup, calls `grim_begin_batch` at `0x00423768`, and
then reloads `render_overlay_player_index` at `0x0042376e` before rebuilding
the player-table address used by both draw coordinates. The previous source
kept one `overlay_player` pointer live across that callback.

Writing the two draw coordinates through the indexed player table expresses
the native callback boundary directly. VC6 now reloads the global index once
after `grim_begin_batch` and shares the rebuilt address across x and y, while
leaving the already-recovered flash-vector lifetime intact. The change adds
54.578 fuzzy-weighted bytes, raises the ratio from 57.9464588% to
58.3813071%, and moves the candidate from 2,881 to 2,885 instructions toward
the 3,021-instruction native target. References improve from `444/0/10` to
`448/0/10`.

The retained source has SHA-256
`69e88872af0ebc65643871a25392f8e0ad009c0ca74f0887d477a549ac04b3b4`.

## Fire-overlay type owner

The independent Fire Bullets overlay at `0x004253bb..0x0042544a` has a real
source-ownership asymmetry. Its active flag, life timer, rotation, and draw
position advance through the current 0x40-byte projectile record, but the
type gate at `0x004253cf` reads `[EDI+0x20]`. MLIL SSA traces `EDI` back to
the primary-projectile pointer established at `0x0042418c`; after that pass
finishes it still names `projectile_pool[0x5f]`. Thus the native overlay tests
the last primary record's type for every current record rather than reusing
the current overlay cursor.

An explicit `fire_type_owner` for `projectile_pool[0x5f]` recovers that native
semantic boundary without disturbing the exhausted overlay geometry. The
more literal shared-pointer lifetime spellings are globally regressive, while
placing this fixed owner immediately before the overlay is the smallest
tradeoff-free form. It adds 4.250 fuzzy-weighted bytes, raises the ratio from
58.3813071% to 58.4151710%, and keeps the candidate at 2,885/3,021
instructions with the same `448/0/10` reference audit.

The retained source has SHA-256
`ca0add177b6fdef14fa5477c7883ab2a49996cb4c095fd59102f0f97a298146b`.
