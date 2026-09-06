# Remaining EXE matching batches

Snapshot: 642-exact source checkpoint, refreshed on 2026-09-07. The native audit
and matching checkpoint reproduce all 671 EXE candidates, including the 29 remaining functions.
The [eight exact recoveries](EXACT-MATCHES-2026-09-07.md) also improve statistics formatting
and bonus pickup publication. They follow the [five-target follow-up](FRONTIER-FOLLOWUP-2026-09-06.md),
[UI storage recovery](UI-STORAGE-FOLLOWUP-2026-09-05.md),
[two exact UI recoveries](EXACT-FOLLOWUP-2026-09-05.md), and
[32-function batches 01–08 pass](BATCHES-01-08-RESULTS.md).

**EXE: 642/671 exact; Grim: 139/139 exact.** The EXE frontier is 29 functions spanning 138,323
code bytes, with 29,639 fuzzy-gap bytes. The top five functions hold 69.1% of that gap, and the
top ten hold 87.2%. Fuzzy gap is size × (1 − alignment ratio), not a count of independently
wrong executable bytes. Exact means normalized instruction identity with all masked references
resolved and equal.

Batches 01–08 have received focused follow-ups; batch 05 is complete. Their remaining members
need a new hypothesis or an interaction supported by the recorded results. Batch 09 has received focused tutorial
and grid-template probes; creature rendering remains next within that group. Batch 12 has a
retained tint gain and bounded secondary-render controls. Batches 10–14 still need region-sized
campaigns, with the smaller UI and worker findings available as controls. Keep batch IDs stable as exact members leave the frontier. Batch
membership describes related work, not an estimate that every member will become exact in one
session.

Recent wins invalidate a blanket “compiler residual” stop rule. Player firing, the trial overlay,
UI elements, and the quest menu now match through interactions between vector expressions and
later value lifetimes. Both database separators match through a shared expression boundary;
perk callbacks and creature initialization recover their native ownership and publication order.
Treat previous negative sweeps as bounds on their specific source forms and baseline, and use
successful siblings as controls rather than templates to copy mechanically.

## Batch index

| Batch | Focus | Functions | Fuzzy gap, bytes |
|---|---|---:|---:|
| [01](#batch-01) | Scalar ownership and shared control flow | 3 | 232 |
| [02](#batch-02) | Spawn records and quest induction | 4 | 340 |
| [03](#batch-03) | WinInet request and response workers | 2 | 750 |
| [04](#batch-04) | Short coordinate lifetimes | 2 | 46 |
| [05](#batch-05) | UI call scheduling and vector primitives | 0 | 0 |
| [06](#batch-06) | Menu object and aggregate lifetimes | 2 | 340 |
| [07](#batch-07) | UI loops, formatting, and board state | 3 | 890 |
| [08](#batch-08) | HUD and effect rendering | 4 | 2,028 |
| [09](#batch-09) | Creature templates, atlas passes, and tutorial stages | 3 | 2,816 |
| [10](#batch-10) | High-score screen | 1 | 1,731 |
| [11](#batch-11) | Player simulation and weapon dispatch | 1 | 5,849 |
| [12](#batch-12) | Projectile simulation and rendering | 2 | 8,324 |
| [13](#batch-13) | Creature simulation lifecycle | 1 | 2,403 |
| [14](#batch-14) | Controls menu and repeated dispatch | 1 | 3,891 |

Individual and batch gaps are rounded independently. Each function appears in exactly one batch
below. Tables show candidate/native instruction counts, mismatched aligned references (all
unresolved counts are zero), and baseline-aware experiment evidence: **H** historical-only,
**A** current-active, **S** current-stalled, **I** current-inconclusive. The checkpoint has 17 H
functions and 12 with current records (8 A, 3 S, 1 I). Retained source changes start a new baseline epoch, so H
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
uv run crimson match scratch tools/match/scratches/bonus_pick_random_type --regions --max-regions 8
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

Three small functions remain after [perk_apply](scratches/perk_apply/NOTES.md) became exact.
Its callback loops retain a cached player count while pure loops read the configured count.
The remaining functions expose distinct ownership and phase boundaries; reconstruct their
dependencies before changing syntax.

| Function / detailed evidence | Match | Insns C/N | Gap | Ref mismatches | Evidence |
|---|---:|---:|---:|---:|:---:|
| [sfx_entry_start_playback](scratches/sfx_entry_start_playback/NOTES.md) | 87.10% | 93/93 | 28 | 0 | S |
| [bonus_pick_random_type](scratches/bonus_pick_random_type/NOTES.md) | 75.93% | 162/162 | 117 | 0 | A |
| [creature_handle_death](scratches/creature_handle_death/NOTES.md) | 89.49% | 205/204 | 88 | 0 | A |

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

Use the newly exact [creature_spawn](scratches/creature_spawn/NOTES.md), indexed quest builders,
and fx_queue_add as calibration examples. Creature initialization needed separate initialization
and finalization helpers plus the exact native health literal. Work on one record-construction
boundary at a time; the successful idiom may differ between functions.

| Function / detailed evidence | Match | Insns C/N | Gap | Ref mismatches | Evidence |
|---|---:|---:|---:|---:|:---:|
| [quest_build_spiders_inc](scratches/quest_build_spiders_inc/NOTES.md) | 95.24% | 105/105 | 16 | 0 | S |
| [quest_spawn_timeline_update](scratches/quest_spawn_timeline_update/NOTES.md) | 91.23% | 113/115 | 32 | 0 | A |
| [quest_build_survival_of_the_fastest](scratches/quest_build_survival_of_the_fastest/NOTES.md) | 79.39% | 228/228 | 177 | 0 | H |
| [projectile_spawn](scratches/projectile_spawn/NOTES.md) | 71.67% | 114/126 | 113 | 0 | H |

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
| [statistics_update_check_worker](scratches/statistics_update_check_worker/NOTES.md) | 78.38% | 373/367 | 297 | 0 | H |

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

Two remain after [player_fire_weapon](scratches/player_fire_weapon/NOTES.md) and
[demo_trial_overlay_render](scratches/demo_trial_overlay_render/NOTES.md) became exact, joining
credits_screen_update. Both remaining functions have equal instruction counts and clean
references. Map where each vector is born, passed by address, and becomes dead, including later
calls that can affect an earlier stack slot.

| Function / detailed evidence | Match | Insns C/N | Gap | Ref mismatches | Evidence |
|---|---:|---:|---:|---:|:---:|
| [survival_update](scratches/survival_update/NOTES.md) | 98.21% | 504/504 | 38 | 0 | S |
| [play_game_menu_update](scratches/play_game_menu_update/NOTES.md) | 99.74% | 777/777 | 8 | 0 | I |

- **survival_update:** Only the first three scripted spawn positions use a different temporary pair;
  native reuses a dead centroid slot. Later stages already align. Inspect the centroid-to-first-wave
  boundary. Numerous scopes and explicit centroid/vector reuse variants either materialize extra
  coordinates or disturb allocation.
- **play_game_menu_update:** Two opening Y-sum operands use a different stack slot. Inspect the
  later button/row lifetime that could color this opening temporary. Opening declarations, row
  copies, and footer scopes have not recovered it; do not confine analysis to the first mismatch.

<a id="batch-05"></a>

## 05 — UI call scheduling and vector primitives

Complete. [ui_cursor_render](scratches/ui_cursor_render/NOTES.md) was already exact;
[unlocked_weapons_database_update](scratches/unlocked_weapons_database_update/NOTES.md),
[unlocked_perks_database_update](scratches/unlocked_perks_database_update/NOTES.md), and
[ui_element_render](scratches/ui_element_render/NOTES.md) now also have normalized and
encoded-body identity.

Both database screens recover the separator schedule by passing its position by value and its
measured integer width by const reference to an inline draw helper. UI element rendering uses
the authenticated SDK vector expressions and their union-backed array view. These recoveries
change only local scratches; shared headers and compiler settings are unchanged. Keep this batch
ID reserved for its completed group.

<a id="batch-06"></a>

## 06 — Menu object and aggregate lifetimes

Two screens/initializers remain after [quest_select_menu_update](scratches/quest_select_menu_update/NOTES.md)
became exact, joining options_menu_update and perk_selection_screen_update. The quest menu needed
interacting panel, row, index, checkbox, and Back-button owners. Use existing authenticated UI
declarations as evidence, while keeping changes local until a common owner is demonstrated.

| Function / detailed evidence | Match | Insns C/N | Gap | Ref mismatches | Evidence |
|---|---:|---:|---:|---:|:---:|
| [mods_menu_update](scratches/mods_menu_update/NOTES.md) | 98.92% | 648/648 | 28 | 0 | A |
| [ui_menu_layout_init](scratches/ui_menu_layout_init/NOTES.md) | 95.69% | 1408/1422 | 312 | 0 | H |

- **mods_menu_update:** Short separator and independent button lifetimes recovered all opening,
  selected-mod rendering, and button instructions, reaching 98.92%. Seven differences remain:
  the 0x154 versus 0x144 frame and five enumeration-buffer addresses. Version rendering now agrees.
  Narrow enumeration scopes, buffer declaration placement, and inline helpers are neutral on this
  improved source; recover the remaining storage ownership without inventing buffer sizes.

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
| [statistics_menu_update](scratches/statistics_menu_update/NOTES.md) | 94.53% | 676/676 | 157 | 0 | A |
| [credits_secret_alien_zookeeper_update](scratches/credits_secret_alien_zookeeper_update/NOTES.md) | 83.86% | 638/638 | 422 | 0 | H |

- **ui_scrollbar_update:** Constructing the row origin directly from x minus two raised alignment
  to 82.43%, preserving 477/479 instructions, prefix 26, and 62 clean references. Typed row indices
  and an input copy regressed; a column local was neutral. Inspect one unmatched row/drag transition
  and its temporary lifetime before broadening the rewrite.

- **statistics_menu_update:** Capturing the session renderer after deriving hours and reusing
  minute/second locals for their remainders recovers the missing instruction and raises alignment
  to 94.53%, preserving prefix 280 and 276 clean references. Session renderer/hour allocation and
  total-time formatting still differ. Follow-up quotient and gate controls gained score only by
  losing an instruction; keep the recovered remainder scheduling intact.
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
| [bonus_hud_slot_update_and_render](scratches/bonus_hud_slot_update_and_render/NOTES.md) | 79.80% | 407/405 | 316 | 0 | H |
| [bonus_render](scratches/bonus_render/NOTES.md) | 92.65% | 1088/1088 | 301 | 0 | A |
| [ui_render_hud](scratches/ui_render_hud/NOTES.md) | 88.29% | 1823/1824 | 829 | 0 | H |
| [player_render_overlays](scratches/player_render_overlays/NOTES.md) | 87.29% | 1141/1148 | 583 | 0 | H |

- **bonus_hud_slot_update_and_render:** Native delays the render-only EDI save until after the
  off-screen return, and the compact arm falls through to the shared tail. Candidate places the
  single-bar arm differently. Recover cursor/color ownership across culling and bar rendering. Prior
  shared-tail score gains introduced a mismatched call reference.
- **bonus_render:** Direct indexed telekinetic pickup publication recovers the missing instruction,
  raises alignment to 92.65%, and improves clean references from 229 to 232. The indexed search also
  recovers the native signed loop bound. The beam region still spills/reloads unscaled width
  differently; trace width, height, and scale consumption across its calls. Named-scale, pointer,
  and separate-height forms did not recover that spill.
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

Three domain-focused targets need narrow internal slices. Creature rendering is next; select one
atlas, detail, or flash pass using the recorded field and call anchors. Reopen tutorial stage five
or a creature template after identifying a new source dependency.

| Function / detailed evidence | Match | Insns C/N | Gap | Ref mismatches | Evidence |
|---|---:|---:|---:|---:|:---:|
| [tutorial_timeline_update](scratches/tutorial_timeline_update/NOTES.md) | 76.76% | 686/695 | 676 | 1 | A |
| [creature_spawn_template](scratches/creature_spawn_template/NOTES.md) | 88.89% | 3161/3159 | 1,566 | 1 | H |
| [creature_render_type](scratches/creature_render_type/NOTES.md) | 79.74% | 760/765 | 574 | 5 | H |

- **tutorial_timeline_update:** Stage-five formation construction remains a large region at
  0x00409175. Twenty-three complete branch-join and escaped-workspace controls regressed. Preserve
  the common third alien spawn and seek a new lifetime boundary before reopening those forms.
  Its lone reference mismatch is the displaced bonus jump table.
- **creature_spawn_template:** Moving the grid-child aggregate tint after stat publication improves
  alignment to 88.89%; changing loop induction reduces that gain. Two extra instructions remain.
  The lone reference mismatch is a retry jump table displaced by body-size differences. Choose
  another bounded publication sequence; avoid whole-dispatcher initializer churn.
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
| [projectile_update](scratches/projectile_update/NOTES.md) | 62.88% | 2183/2203 | 3,121 | 13 | H |
| [projectile_render](scratches/projectile_render/NOTES.md) | 58.55% | 2885/3021 | 5,202 | 10 | A |

- **projectile_update:** 20 fewer instructions, 13 reference mismatches, and a native frame larger
  by 0x30. Partition movement/collision, impact/decal, child-spawn, and lifetime publication. Start
  with a reference-bearing region outside the repeatedly tested decal scale, Plasma-child staging,
  and particle geometry. Primary-impact double jitter gained score by removing three more
  instructions, so it is not a retained solution. A uniform const-reference tint clamp now recovers
  seven instructions and removes five reference mismatches; in-place helper forms that lose an
  instruction remain rejected.
- **projectile_render:** 136 fewer instructions, ten reference mismatches, and a native frame of
  0x19c versus candidate 0x128. Partition Sharpshooter, conventional trails, plasma-family trails,
  primary ion/fire, overlays/billboards, and secondary passes. Choose one pass with a demonstrable
  missing materialization and audit its neighbors. SDK operator sweeps, Fire cross-pass owners, and
  billboard aggregate temporaries already regressed. The 0x74 frame delta is a clue to lifetimes,
  not a request for padding. Eleven secondary glow and sprite-boundary controls are byte-neutral;
  larger conventional/ion regions remain independent work.

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
