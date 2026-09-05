# Remaining EXE matching batches

Snapshot: `5ab2935e2` (633-exact source checkpoint), refreshed on 2026-09-05. The native audit
and matching checkpoint reproduce all 671 EXE candidates, including the 38 remaining functions.
The [latest UI storage follow-up](UI-STORAGE-FOLLOWUP-2026-09-05.md) improved the mods menu to
98.92% after the [two exact UI recoveries](EXACT-FOLLOWUP-2026-09-05.md) and the
[32-function batches 01–08 pass](BATCHES-01-08-RESULTS.md).

**EXE: 633/671 exact; Grim: 139/139 exact.** The EXE frontier is 38 functions spanning 153,591
code bytes, with 30,031 fuzzy-gap bytes. The top five functions hold 68.2% of that gap, and the
top ten hold 86.2%. Fuzzy gap is size × (1 − alignment ratio), not a count of independently
wrong executable bytes. Exact means normalized instruction identity with all masked references
resolved and equal.

Batches 01–08 have received a focused first pass; their remaining members need a new hypothesis
or an interaction supported by the recorded results. Batch 09 is the next unworked focused
group. Batches 10–14 need region-sized campaigns, with the smaller UI and worker findings
available as controls. Keep batch IDs stable as exact members leave the frontier. Batch
membership describes related work, not an estimate that every member will become exact in one
session.

Recent wins invalidate a blanket “compiler residual” stop rule. Options, perk selection, and
credits now match exactly through interactions between opening values and later UI coordinate
lifetimes. Worker initialization, quest publication, and menu/scrollbar scheduling also improved.
Treat previous negative sweeps as bounds on their specific source forms and baseline, and use
successful siblings as controls rather than templates to copy mechanically.

## Batch index

| Batch | Focus | Functions | Fuzzy gap, bytes |
|---|---|---:|---:|
| [01](#batch-01) | Scalar ownership and shared control flow | 4 | 236 |
| [02](#batch-02) | Spawn records and quest induction | 5 | 378 |
| [03](#batch-03) | WinInet request and response workers | 2 | 750 |
| [04](#batch-04) | Short coordinate lifetimes | 4 | 103 |
| [05](#batch-05) | UI call scheduling and vector primitives | 4 | 54 |
| [06](#batch-06) | Menu object and aggregate lifetimes | 3 | 481 |
| [07](#batch-07) | UI loops, formatting, and board state | 3 | 926 |
| [08](#batch-08) | HUD and effect rendering | 4 | 2,053 |
| [09](#batch-09) | Creature templates, atlas passes, and tutorial stages | 3 | 2,834 |
| [10](#batch-10) | High-score screen | 1 | 1,731 |
| [11](#batch-11) | Player simulation and weapon dispatch | 1 | 5,849 |
| [12](#batch-12) | Projectile simulation and rendering | 2 | 8,342 |
| [13](#batch-13) | Creature simulation lifecycle | 1 | 2,403 |
| [14](#batch-14) | Controls menu and repeated dispatch | 1 | 3,891 |

Individual and batch gaps are rounded independently. Each function appears in exactly one batch
below. Tables show candidate/native instruction counts, mismatched aligned references (all
unresolved counts are zero), and baseline-aware experiment evidence: **H** historical-only,
**A** current-active, **S** current-stalled, **I** current-inconclusive. The checkpoint has 11 H
functions and 27 with current records. Retained source changes start a new baseline epoch, so H
can include a function improved in this pass; the campaign report preserves the gain evidence. H
does not mean untouched; S means at least three complete, error-free, non-improving sweeps at
that baseline, not an impossibility proof.

## How to run a batch

1. Reproduce each selected baseline; read its linked notes and current source/config. Map one native
   mismatch region to the source values, calls, and lifetime/phase boundaries. A mismatch hint or a
   stale NOTES conclusion is not a root cause.
2. State one falsifiable hypothesis and inspect an exact sibling where available. Test a small set
   of complete, behavior-preserving forms, then interactions only if the individual evidence
   supports them. Keep source evaluation scoped to one function or region at a time.
3. Accept a source change only with native-backed improvement and no regression in existing exact
   functions, prefix/reference fidelity, or instruction recovery. A higher fuzzy score alone is
   insufficient. For existing reference debt, require no increase and inspect any change in the
   reference alignment.
4. Record the tested route and result at the current baseline. If the hypothesis is falsified, move
   to the next region or member; reopen it after a baseline change or new source/native evidence. Do
   not convert a finite negative sweep into a global compiler limitation.
5. Commit each coherent gain with its notes. Refresh the native audit and checkpoint before
   reporting campaign totals. Keep shared-header/TU changes for demonstrated shared ownership and
   verify all affected consumers.

```sh
uv run crimson match scratch tools/match/scratches/perk_apply --regions --max-regions 8
# Replace the scratch name for the selected member; add --json for structured regions.
# After retaining a coherent source change:
just native-audit crimsonland.exe
uv run crimson match checkpoint -j 8
```

A WIP scratch returns a nonzero match result; inspect its metrics separately from compiler/tool
failures. For large routines, localized regions and CFG pairing are diagnostic aids: verify
repeated/switch-block pairings before interpreting missing blocks or references.

<a id="batch-01"></a>

## 01 — Scalar ownership and shared control flow

The first pass retained no changes in these four small functions. They expose ownership and
phase boundaries similar to those behind recent exact matches. Reconstruct the dependency before
changing syntax.

| Function / detailed evidence | Match | Insns C/N | Gap | Ref mismatches | Evidence |
|---|---:|---:|---:|---:|:---:|
| [perk_apply](scratches/perk_apply/NOTES.md) | 99.59% | 241/241 | 4 | 0 | S |
| [sfx_entry_start_playback](scratches/sfx_entry_start_playback/NOTES.md) | 87.10% | 93/93 | 28 | 0 | A |
| [bonus_pick_random_type](scratches/bonus_pick_random_type/NOTES.md) | 75.93% | 162/162 | 117 | 0 | A |
| [creature_handle_death](scratches/creature_handle_death/NOTES.md) | 89.49% | 205/204 | 88 | 0 | I |

- **perk_apply:** Bandage materializes the health cursor before the count guard; native does it
  after. Everything else now aligns (241 instructions, prefix 193). Trace why this one loop carries
  the cursor across the guard while the Ammo Maniac loop does not. Direct configured-count loops
  already recovered the broad register allocation; nested guards and indexed player rewrites
  reverted that gain.
- **sfx_entry_start_playback:** Native saves ESI before the streaming arm but initializes its
  resident index after that arm returns. Candidate initializes it early; moving the initialization
  has instead moved the save into the resident arm. Reconstruct the restore/stream/resident result
  lifetimes together. Call-owner permutations and simple shared-return shapes have failed; every
  path must initialize any consumed local.
- **bonus_pick_random_type:** The quest-stage Nuke rejection occupies a cold block after the native
  final return. Candidate keeps it inline despite equal total instruction counts. Separate the
  eligibility and selection phases using their actual state dependencies. Predicate inversion,
  switch rewrites, and synthetic shared-return shapes have already been tested.
- **creature_handle_death:** One extra opening shift comes from commoning the creature-index scale
  before the flag access. Inspect which value owns the flag test versus the later record pointer,
  using the newly exact creature_apply_damage as a control-flow comparison. All-index,
  pointer/reference, and helper variants have not yet removed this extra operation cleanly.

<a id="batch-02"></a>

## 02 — Spawn records and quest induction

Use the newly exact indexed quest builders and fx_queue_add as calibration examples. Work on one
record-construction boundary at a time; the successful idiom may differ between functions.

| Function / detailed evidence | Match | Insns C/N | Gap | Ref mismatches | Evidence |
|---|---:|---:|---:|---:|:---:|
| [quest_build_spiders_inc](scratches/quest_build_spiders_inc/NOTES.md) | 95.24% | 105/105 | 16 | 0 | S |
| [quest_spawn_timeline_update](scratches/quest_spawn_timeline_update/NOTES.md) | 91.23% | 113/115 | 32 | 0 | A |
| [quest_build_survival_of_the_fastest](scratches/quest_build_survival_of_the_fastest/NOTES.md) | 79.39% | 228/228 | 177 | 0 | H |
| [creature_spawn](scratches/creature_spawn/NOTES.md) | 88.61% | 79/79 | 38 | 0 | I |
| [projectile_spawn](scratches/projectile_spawn/NOTES.md) | 71.67% | 114/126 | 113 | 0 | S |

- **quest_build_spiders_inc:** The wave count is computed before the pointer calculation in native
  but stored after coordinates. Candidate gets the registers right by storing it early. Recover a
  real per-wave record/range boundary from the sibling builders. Earlier early-store full-index
  forms gained score but lost an aligned reference; simple late-count forms rotated registers.
- **quest_spawn_timeline_update:** Native retains an interior template-id cursor and a temporary
  stack home later reused for spread; candidate folds these into the entry base and emits two fewer
  instructions. Trace the template, heading, and spread values through one spawn group. Typed-entry,
  vector-constructor, and metadata-owner variations have already bounded the obvious spellings.
- **quest_build_survival_of_the_fastest:** The three late path edges now publish directly through the
  indexed spawn record, raising alignment to 79.39% with 228/228 instructions. First-edge indexing
  regressed, and a postincrement count was neutral. Revisit the early counter/loop ownership with
  the retained late edges as controls; a fixed twelve-entry count still specializes away later loops.

- **creature_spawn:** Native and candidate have the same instruction count but differ in x87 health
  scheduling and size/color publication. Inspect initialization dependencies around the actual
  creature owner. Merely switching C/C++ or wrapping position, velocity, and color in aggregates did
  not help.
- **projectile_spawn:** Native retains a default damage value and a fire-bullet override backedge;
  candidate constant propagation removes twelve instructions. Revisit the initializer and override
  phase ownership against its callers. Shared-tail, loop, and value-ABI spellings have failed; an
  artificial spill of 1.0 would not establish the source boundary.

<a id="batch-03"></a>

## 03 — WinInet request and response workers

A compact two-function batch with 750 rounded gap bytes after the worker initialization gain.
Compare genuine sibling request/cleanup lifetimes; both reference audits are clean and both
target extents already include their epilogues.

| Function / detailed evidence | Match | Insns C/N | Gap | Ref mismatches | Evidence |
|---|---:|---:|---:|---:|:---:|
| [highscore_sync_worker](scratches/highscore_sync_worker/NOTES.md) | 77.14% | 525/525 | 453 | 0 | H |
| [statistics_update_check_worker](scratches/statistics_update_check_worker/NOTES.md) | 78.38% | 373/367 | 297 | 0 | S |

- **highscore_sync_worker:** Zeroing the complete 64-byte request path before literal character
  publication recovered the native initialization shape: 77.14%, 525/525 instructions, 119 clean
  references. Host-character publication and shared report tails introduced metric tradeoffs.
  Next inspect the outgoing field cursor, received-record publication, or MIME/cleanup ownership;
  keep the recovered request-path boundary intact.

- **statistics_update_check_worker:** Separate the path literal initialization, request-only MIME
  array, and version-output lifetimes. Native /ra_version.php stores differ from current array
  lowering; use the sibling worker to check actual initialization and handle scopes. Manual path
  stores plus a longer MIME lifetime have gained score only with extra instructions. Handle and
  version-local declaration permutations are byte-neutral.

<a id="batch-04"></a>

## 04 — Short coordinate lifetimes

These four remain after credits_screen_update became exact; all have equal instruction counts
and clean references. Map where each vector is born, passed by address, and becomes dead,
including later calls that can affect an earlier stack slot.

| Function / detailed evidence | Match | Insns C/N | Gap | Ref mismatches | Evidence |
|---|---:|---:|---:|---:|:---:|
| [player_fire_weapon](scratches/player_fire_weapon/NOTES.md) | 99.21% | 378/378 | 12 | 0 | A |
| [survival_update](scratches/survival_update/NOTES.md) | 98.21% | 504/504 | 38 | 0 | A |
| [play_game_menu_update](scratches/play_game_menu_update/NOTES.md) | 99.74% | 777/777 | 8 | 0 | S |
| [demo_trial_overlay_render](scratches/demo_trial_overlay_render/NOTES.md) | 98.11% | 636/636 | 46 | 0 | A |

- **player_fire_weapon:** Only the pellet position stack operands remain: native uses the upper
  position pair after the two sprite calls, candidate the lower pair. Trace both calls and pellet
  generation as one lifetime graph. Fresh vectors, simple reuse, SDK forms, and movement-zero
  separation already failed.
- **survival_update:** Only the first three scripted spawn positions use a different temporary pair;
  native reuses a dead centroid slot. Later stages already align. Inspect the centroid-to-first-wave
  boundary. Numerous scopes and explicit centroid/vector reuse variants either materialize extra
  coordinates or disturb allocation.
- **play_game_menu_update:** Two opening Y-sum operands use a different stack slot. Inspect the
  later button/row lifetime that could color this opening temporary. Opening declarations, row
  copies, and footer scopes have not recovered it; do not confine analysis to the first mismatch.

- **demo_trial_overlay_render:** Three regions remain around the expired suffix and complementary
  Purchase/Maybe Later coordinates; the quest suffix already matches. Compare branch-exclusive
  coordinate owners and the shared draw tail. Direct suffix reuse merges native operations;
  dedicated expired vectors and copies have not solved the lifetime.

<a id="batch-05"></a>

## 05 — UI call scheduling and vector primitives

Treat the database screens as a sibling pair. Very small gaps make these precise experiments,
not guaranteed quick wins. Any proposed shared-header correction needs independent type evidence
and checks of its exact consumers.

| Function / detailed evidence | Match | Insns C/N | Gap | Ref mismatches | Evidence |
|---|---:|---:|---:|---:|:---:|
| [unlocked_weapons_database_update](scratches/unlocked_weapons_database_update/NOTES.md) | 99.81% | 523/523 | 4 | 0 | A |
| [unlocked_perks_database_update](scratches/unlocked_perks_database_update/NOTES.md) | 99.80% | 511/511 | 4 | 0 | S |
| [ui_cursor_render](scratches/ui_cursor_render/NOTES.md) | 98.87% | 177/177 | 8 | 0 | S |
| [ui_element_render](scratches/ui_element_render/NOTES.md) | 97.89% | 521/521 | 38 | 0 | S |

- **unlocked_weapons_database_update:** One title-separator schedule inversion: native loads the
  renderer vtable before converting title width with fild. Compare its expression boundary with the
  perks screen and exact drawing callers. Scalar width types, renderer aliases, wrappers,
  neighboring TUs, and compiler profiles have already tied or regressed.
- **unlocked_perks_database_update:** The same title-separator inversion as the weapons screen. Test
  one shared, evidence-backed expression hypothesis on both screens. A recovered UI owner previously
  preserved code shape but introduced reference mismatches, so it was not a clean match.
- **ui_cursor_render:** The final quad starts the mouse-Y-minus-two calculation before argument
  pushes/vtable work in native. Inspect this final call and the lifetime of its argument vector.
  Scalar/vector/helper and aggregate-owner probes did not fix it; extra materialization added
  instructions and reference debt.
- **ui_element_render:** Three panel Y additions and the counter-X temporary retain different
  operand/slot choices. Compare the counter shadow and final draw operand lifetimes against the
  already recovered shared position. Broad shared-position rewrites and vector operator/value
  variants have not helped.

<a id="batch-06"></a>

## 06 — Menu object and aggregate lifetimes

Three screens/initializers remain after options_menu_update and perk_selection_screen_update
became exact. Use existing authenticated UI declarations as evidence, while keeping changes
local until a common owner is demonstrated.

| Function / detailed evidence | Match | Insns C/N | Gap | Ref mismatches | Evidence |
|---|---:|---:|---:|---:|:---:|
| [mods_menu_update](scratches/mods_menu_update/NOTES.md) | 98.92% | 648/648 | 28 | 0 | H |
| [quest_select_menu_update](scratches/quest_select_menu_update/NOTES.md) | 95.89% | 803/803 | 141 | 0 | A |
| [ui_menu_layout_init](scratches/ui_menu_layout_init/NOTES.md) | 95.69% | 1408/1422 | 312 | 0 | H |

- **mods_menu_update:** Short separator and independent button lifetimes recovered all opening,
  selected-mod rendering, and button instructions, reaching 98.92%. Seven differences remain:
  the 0x154 versus 0x144 frame and five enumeration-buffer addresses. Version rendering now agrees.
  Narrow enumeration scopes, buffer declaration placement, and inline helpers are neutral on this
  improved source; recover the remaining storage ownership without inventing buffer sizes.
- **quest_select_menu_update:** Both frames are 48 bytes. Opening panel-Y/hover stores and the
  Back-button x87 reload remain locally reordered, with further row/register differences. Inspect
  the interaction between the recovered checkbox and surrounding row/Back scopes. Opening-store
  permutations and short Back-vector construction forms have already been replayed.

- **ui_menu_layout_init:** Publishing slot 31 position immediately after copy_layer and before
  hover_max construction raised alignment to 95.69%, preserving prefix 467 and improving clean
  references to 529. A shared vector temporary tied this result. Native still retains fourteen
  operations absent from candidate; inspect later coordinate preservation and publication without
  deleting native Y load/store pairs.

<a id="batch-07"></a>

## 07 — UI loops, formatting, and board state

Use short-lived interaction/formatting scopes to explain the values that survive into rendering.
These are medium-sized functions with clean references, but whole-function allocation still
matters.

| Function / detailed evidence | Match | Insns C/N | Gap | Ref mismatches | Evidence |
|---|---:|---:|---:|---:|:---:|
| [ui_scrollbar_update](scratches/ui_scrollbar_update/NOTES.md) | 82.43% | 477/479 | 311 | 0 | H |
| [statistics_menu_update](scratches/statistics_menu_update/NOTES.md) | 93.26% | 675/676 | 194 | 0 | A |
| [credits_secret_alien_zookeeper_update](scratches/credits_secret_alien_zookeeper_update/NOTES.md) | 83.86% | 638/638 | 422 | 0 | S |

- **ui_scrollbar_update:** Constructing the row origin directly from x minus two raised alignment
  to 82.43%, preserving 477/479 instructions, prefix 26, and 62 clean references. Typed row indices
  and an input copy regressed; a column local was neutral. Inspect one unmatched row/drag transition
  and its temporary lifetime before broadening the rewrite.

- **statistics_menu_update:** Session-time formatting assigns hours and the renderer to different
  EBP/EDI roles; total-time arithmetic crosses the F1 gate differently. Recover the formatting-call
  inputs and their live ranges. Independent quotient/renderer declarations and explicit seconds
  subtraction have not recovered the native schedule.
- **credits_secret_alien_zookeeper_update:** Panel-expression and long-lived board vectors occupy
  opposite stack pairs despite equal 0x54 frames and instruction counts. Inspect later board
  consumers for an ownership/lifetime explanation. Reordering the two declarations, copying
  components, and vector operator-shape sweeps have already failed; the early pair alone is
  insufficient.

<a id="batch-08"></a>

## 08 — HUD and effect rendering

Four renderers offer smaller controls before the large projectile renderer. Preserve pass
boundaries, direct pool ownership, callback ordering, and rounded x87 intermediates.

| Function / detailed evidence | Match | Insns C/N | Gap | Ref mismatches | Evidence |
|---|---:|---:|---:|---:|:---:|
| [bonus_hud_slot_update_and_render](scratches/bonus_hud_slot_update_and_render/NOTES.md) | 79.80% | 407/405 | 316 | 0 | A |
| [bonus_render](scratches/bonus_render/NOTES.md) | 92.05% | 1087/1088 | 325 | 0 | A |
| [ui_render_hud](scratches/ui_render_hud/NOTES.md) | 88.29% | 1823/1824 | 829 | 0 | A |
| [player_render_overlays](scratches/player_render_overlays/NOTES.md) | 87.29% | 1141/1148 | 583 | 0 | A |

- **bonus_hud_slot_update_and_render:** Native delays the render-only EDI save until after the
  off-screen return, and the compact arm falls through to the shared tail. Candidate places the
  single-bar arm differently. Recover cursor/color ownership across culling and bar rendering. Prior
  shared-tail score gains introduced a mismatched call reference.
- **bonus_render:** Direct indexed particle-pool access already closed all references. The remaining
  beam region spills/reloads unscaled width differently; candidate is one instruction short. Trace
  width, height, and scale consumption across the beam calls. Recent named-scale, pointer, and
  separate-height forms did not recover that spill.
- **ui_render_hud:** Candidate is one instruction short; the bonus-popup entry is a known structural
  seam, while the quest banner differs only in temporary slots. Inspect the popup
  conversion/count/icon dependencies before changing the surrounding frame. Six entry-order and six
  popup-origin variants already failed, so use another producer/consumer boundary if those
  dependencies are unchanged.
- **player_render_overlays:** Seven native instructions remain absent after half-size ownership
  recovery. Compare shield, muzzle, and target-trail value construction one pass at a time. Explicit
  SDK vector subtraction improved the score only by deleting another instruction and was rejected;
  local operator cleanup is not enough.

<a id="batch-09"></a>

## 09 — Creature templates, atlas passes, and tutorial stages

Three domain-focused targets need narrow internal slices. Start with tutorial stage five, then
one creature template or one render pass; this batch is not a request to rewrite all three
together.

| Function / detailed evidence | Match | Insns C/N | Gap | Ref mismatches | Evidence |
|---|---:|---:|---:|---:|:---:|
| [tutorial_timeline_update](scratches/tutorial_timeline_update/NOTES.md) | 76.76% | 686/695 | 676 | 1 | A |
| [creature_spawn_template](scratches/creature_spawn_template/NOTES.md) | 88.77% | 3161/3159 | 1,584 | 1 | S |
| [creature_render_type](scratches/creature_render_type/NOTES.md) | 79.74% | 760/765 | 574 | 5 | A |

- **tutorial_timeline_update:** Stage-five formation construction is a large remaining region (near
  0x00409171). Recover the position workspace and odd/even branch join while preserving the common
  third alien spawn. Prior high-scoring partial variants omitted or misplaced that spawn; stage-one
  constructor syntax was byte-neutral.
- **creature_spawn_template:** The large template dispatcher has two extra instructions and one
  mismatched reference. Resolve that reference and choose one unmatched template publication
  sequence. Template 0x13 tint ownership produced a genuine gain; transferring it to root velocity
  or template 0x11 did not. Avoid whole-dispatcher initializer churn.
- **creature_render_type:** Five missing instructions and five reference mismatches remain across
  animation/detail/flash passes. Trace the atlas publication and exact creature field anchors per
  pass. Flash/main cursor rewrites reduced individual reference mismatches while losing overall
  alignment; typed local views were byte-neutral.

<a id="batch-10"></a>

## 10 — High-score screen

One large UI function per campaign. Smaller menu/list/worker findings can inform this batch, but
exact completion of those batches is not a prerequisite.

| Function / detailed evidence | Match | Insns C/N | Gap | Ref mismatches | Evidence |
|---|---:|---:|---:|---:|:---:|
| [highscore_screen_update](scratches/highscore_screen_update/NOTES.md) | 78.43% | 1969/2004 | 1,731 | 4 | H |

- **highscore_screen_update:** Thirty-five instructions and four aligned references remain to
  recover. Partition into list/drop-list setup, local/online selection, row rendering, and
  submission/exit. First identify the four actual reference sites and a structural
  missing-instruction region. Keep the recovered drop-list/checkbox constructor order and bounded
  listbox clear; reverting them to generic memset or opposite store chains already regressed.

<a id="batch-11"></a>

## 11 — Player simulation and weapon dispatch

The largest individual fuzzy gap. Begin with a region map and one weapon/control phase, not a
full-function rewrite. Run full-function matching after every local experiment because distant
allocation changes are common.

| Function / detailed evidence | Match | Insns C/N | Gap | Ref mismatches | Evidence |
|---|---:|---:|---:|---:|:---:|
| [player_update](scratches/player_update/NOTES.md) | 64.02% | 4066/4206 | 5,849 | 2 | H |

- **player_update:** 140 fewer candidate instructions and two reference mismatches remain, despite
  identical 0x48 prologue allocations. Partition input/movement, aiming, weapon dispatch, and late
  publication/clamps. Recent pellet-position lifetime recoveries prove this target is still
  improvable. Audit the largest current mismatch spans near 0x00414805 and 0x004168c2, then pick a
  dependency not already covered by the one-shot/Multi Plasma move_delta probes; those caused
  roughly 800-byte regressions. Do not add locals to an already equal frame.

<a id="batch-12"></a>

## 12 — Projectile simulation and rendering

Two related functions, executed as separate region campaigns: simulation first, rendering
second. Reuse only demonstrated pool/value ownership; each function has different native stack
lifetimes.

| Function / detailed evidence | Match | Insns C/N | Gap | Ref mismatches | Evidence |
|---|---:|---:|---:|---:|:---:|
| [projectile_update](scratches/projectile_update/NOTES.md) | 62.66% | 2176/2203 | 3,140 | 18 | H |
| [projectile_render](scratches/projectile_render/NOTES.md) | 58.55% | 2885/3021 | 5,202 | 10 | H |

- **projectile_update:** 27 fewer instructions, 18 reference mismatches, and a native frame larger
  by 0x30. Partition movement/collision, impact/decal, child-spawn, and lifetime publication. Start
  with a reference-bearing region outside the repeatedly tested decal scale, Plasma-child staging,
  and particle geometry. Primary-impact double jitter gained score by removing three more
  instructions, so it is not a retained solution.
- **projectile_render:** 136 fewer instructions, ten reference mismatches, and a native frame of
  0x19c versus candidate 0x128. Partition Sharpshooter, conventional trails, plasma-family trails,
  primary ion/fire, overlays/billboards, and secondary passes. Choose one pass with a demonstrable
  missing materialization and audit its neighbors. SDK operator sweeps, Fire cross-pass owners, and
  billboard aggregate temporaries already regressed. The 0x74 frame delta is a clue to lifetimes,
  not a request for padding.

<a id="batch-13"></a>

## 13 — Creature simulation lifecycle

A single large loop with a high byte payoff. Use explicit live/dead phase boundaries and
individual AI modes as work units.

| Function / detailed evidence | Match | Insns C/N | Gap | Ref mismatches | Evidence |
|---|---:|---:|---:|---:|:---:|
| [creature_update_all](scratches/creature_update_all/NOTES.md) | 54.91% | 1299/1338 | 2,403 | 2 | H |

- **creature_update_all:** 39 fewer instructions, two reference mismatches, and a native frame
  larger by 0x10. Partition retargeting, live AI/attacks, infection, and dead/corpse publication.
  Recheck the field reads and stores crossing those joins before rewriting vector expressions.
  Orbit-vector, lifecycle-local, and corpse-motion alias menus failed; native quirks such as
  continuing the selected live arm after a damage call must survive any phase recovery.

<a id="batch-14"></a>

## 14 — Controls menu and repeated dispatch

Last by current evidence quality, not declared impossible. Its huge fuzzy gap is dominated by
repeated code where linear alignment is ambiguous; require a native-backed structural lead
before a mutation campaign.

| Function / detailed evidence | Match | Insns C/N | Gap | Ref mismatches | Evidence |
|---|---:|---:|---:|---:|:---:|
| [controls_menu_update](scratches/controls_menu_update/NOTES.md) | 81.72% | 5413/5421 | 3,891 | 9 | H |

- **controls_menu_update:** Eight fewer instructions and nine reference mismatches remain with equal
  0x74 frames. Compare the runtime binding-copy loop, item-reset loop, and individual switch tables
  using stable CFG anchors. Historical analysis found six compiler-local tables among the reference
  issues and many duplicate-exact blocks; heuristic edge conflicts are not proof of wrong branches.
  Reopen a specific unmatched block with fresh ownership evidence rather than repeating generic
  cursor or stack-slot permutations.

## Sources and maintenance

- [Generated matching status](STATUS.md): scope, frontier, and epoch-aware experiment labels.
- [EXE native object manifest](../../analysis/native/crimsonland.exe/objects.json): current function
  extents, source/config hashes, and matching metrics.
- Per-function notes linked above: native addresses, retained recoveries, and bounded negative
  experiments. Read their later entries before relying on introductory metrics.
- [Matching workflow and toolchain evidence](README.md): matcher usage, scope, and compiler
  provenance.

This map changes no matching source, compiler configuration, reference catalog, or scope. After
a gain, remove the exact member, refresh the affected metrics and evidence labels, and
reconsider related batches if the result changes their ownership hypothesis. Historical
addresses and failed probes remain useful evidence, but batch priorities are revisable.