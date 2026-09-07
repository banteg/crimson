# Remaining EXE matching batches

Snapshot: 653-exact source checkpoint, refreshed on 2026-09-07. The native audit
and matching checkpoint reproduce all 671 EXE candidates, including the 18 remaining functions.
This pass adds five exact matches:

- [bonus_hud_slot_update_and_render](scratches/bonus_hud_slot_update_and_render/NOTES.md)
- [statistics_menu_update](scratches/statistics_menu_update/NOTES.md)
- [tutorial_timeline_update](scratches/tutorial_timeline_update/NOTES.md)
- [mods_menu_update](scratches/mods_menu_update/NOTES.md)
- [bonus_render](scratches/bonus_render/NOTES.md)

All five have encoded-body identity, recovering 14,045 exact code bytes. The matcher also
correctly resolves local relative relocations for body comparison, preserves memory segment
overrides, and accounts for addends into compiler constants. The relocation fix recognizes
existing byte identity in console_log_node_free and sfx_mute_all; those are not new source
matches. The segment/addend fixes leave all 810 canonical candidates' metrics unchanged.
The matcher and related validation suites pass 301 tests. The checkpoint against `ac5c74a2f`
reports zero regression, evaluation, metadata, experiment, strict-experiment, scope, and native
errors. Both native artifact sets are current.

This follows the [Play Game recovery](scratches/play_game_menu_update/NOTES.md),
[eight exact recoveries](EXACT-MATCHES-2026-09-07.md),
[five-target follow-up](FRONTIER-FOLLOWUP-2026-09-06.md),
[UI storage recovery](UI-STORAGE-FOLLOWUP-2026-09-05.md),
[two exact UI recoveries](EXACT-FOLLOWUP-2026-09-05.md), and
[32-function batches 01–08 pass](BATCHES-01-08-RESULTS.md).

**EXE: 653/671 exact; Grim: 139/139 exact.** Across both images, 792/810 functions have normalized
identity and 790/810 have encoded-body identity. The EXE frontier is 18 functions spanning 106,461
code bytes, with 26,607 fuzzy-gap bytes. The top five functions hold 76.9% of that gap, and the
top ten hold 96.8%. Fuzzy gap is size × (1 − alignment ratio), not a count of independently
wrong executable bytes. Exact means normalized instruction identity with all masked references
resolved and equal.

Batches 01–08 have received focused follow-ups; batches 04–07 are complete. Their remaining members
need a new hypothesis or an interaction supported by the recorded results. Batch 09's tutorial is
complete; creature templates and rendering remain. Batch 12 has a
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
| [02](#batch-02) | Spawn records and quest induction | 3 | 162 |
| [03](#batch-03) | WinInet request and response workers | 2 | 464 |
| [04](#batch-04) | Short coordinate lifetimes | 0 | 0 |
| [05](#batch-05) | UI call scheduling and vector primitives | 0 | 0 |
| [06](#batch-06) | Menu object and aggregate lifetimes | 0 | 0 |
| [07](#batch-07) | UI loops, formatting, and board state | 0 | 0 |
| [08](#batch-08) | HUD and effect rendering | 2 | 1,412 |
| [09](#batch-09) | Creature templates, atlas passes, and tutorial stages | 2 | 2,140 |
| [10](#batch-10) | High-score screen | 1 | 1,731 |
| [11](#batch-11) | Player simulation and weapon dispatch | 1 | 5,849 |
| [12](#batch-12) | Projectile simulation and rendering | 2 | 8,324 |
| [13](#batch-13) | Creature simulation lifecycle | 1 | 2,403 |
| [14](#batch-14) | Controls menu and repeated dispatch | 1 | 3,891 |

Individual and batch gaps are rounded independently. Each function appears in exactly one batch
below. Tables show candidate/native instruction counts, mismatched aligned references (all
unresolved counts are zero), and baseline-aware experiment evidence: **H** historical-only,
**A** current-active, **S** current-stalled, **I** current-inconclusive. All 18 remaining functions
are H after the matcher changes started a new baseline epoch. Source and matcher changes can
make earlier records historical; the per-function notes preserve their evidence. H
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
| [sfx_entry_start_playback](scratches/sfx_entry_start_playback/NOTES.md) | 87.10% | 93/93 | 28 | 0 | H |
| [bonus_pick_random_type](scratches/bonus_pick_random_type/NOTES.md) | 75.93% | 162/162 | 117 | 0 | H |
| [creature_handle_death](scratches/creature_handle_death/NOTES.md) | 89.49% | 205/204 | 88 | 0 | H |

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
[quest_build_survival_of_the_fastest](scratches/quest_build_survival_of_the_fastest/NOTES.md)
is now byte-exact through separate route and publication counters, a shared route index across
phases, and the fourth-corner vector construction.

| Function / detailed evidence | Match | Insns C/N | Gap | Ref mismatches | Evidence |
|---|---:|---:|---:|---:|:---:|
| [quest_build_spiders_inc](scratches/quest_build_spiders_inc/NOTES.md) | 95.24% | 105/105 | 16 | 0 | H |
| [quest_spawn_timeline_update](scratches/quest_spawn_timeline_update/NOTES.md) | 91.23% | 113/115 | 32 | 0 | H |
| [projectile_spawn](scratches/projectile_spawn/NOTES.md) | 71.67% | 114/126 | 113 | 0 | H |

- **quest_build_spiders_inc:** The wave count is computed before the pointer calculation in native
  but stored after coordinates. Candidate gets the registers right by storing it early. Recover a
  real per-wave record/range boundary from the sibling builders. Earlier early-store full-index
  forms gained score but lost an aligned reference; simple late-count forms rotated registers.
- **quest_spawn_timeline_update:** Native retains an interior template-id cursor and a temporary
  stack home later reused for spread; candidate folds these into the entry base and emits two fewer
  instructions. Trace the template, heading, and spread values through one spawn group. Typed-entry,
  vector-constructor, and metadata-owner variations have already bounded the obvious spellings.
- **projectile_spawn:** Native retains a default damage value and a fire-bullet override backedge;
  candidate constant propagation removes twelve instructions. Revisit the initializer and override
  phase ownership against its callers. Shared-tail, loop, and value-ABI spellings have failed; an
  artificial spill of 1.0 would not establish the source boundary.

<a id="batch-03"></a>

## 03 — WinInet request and response workers

A compact two-function batch with 464 rounded gap bytes after the version-worker recovery.
Compare genuine sibling request/cleanup lifetimes; both reference audits are clean and both
target extents already include their epilogues.

| Function / detailed evidence | Match | Insns C/N | Gap | Ref mismatches | Evidence |
|---|---:|---:|---:|---:|:---:|
| [highscore_sync_worker](scratches/highscore_sync_worker/NOTES.md) | 77.14% | 525/525 | 453 | 0 | H |
| [statistics_update_check_worker](scratches/statistics_update_check_worker/NOTES.md) | 99.18% | 367/367 | 11 | 0 | H |

- **highscore_sync_worker:** Zeroing the complete 64-byte request path before literal character
  publication recovered the native initialization shape: 77.14%, 525/525 instructions, 119 clean
  references. Host-character publication and shared report tails introduced metric tradeoffs.
  Next inspect the outgoing field cursor, received-record publication, or MIME/cleanup ownership;
  keep the recovered request-path boundary intact.

- **statistics_update_check_worker:** MIME initialization before header-length publication,
  character-wise request-path construction, nested request/connection flow, and grouped version
  outputs recover 99.18%, 367/367 instructions, prefix 252, and 120/0/0 references. The remaining
  three instruction differences are the version-output address registers and the URL-store
  schedule immediately before sscanf. This is an improvement, not one of the five new matches.

<a id="batch-04"></a>

## 04 — Short coordinate lifetimes

Complete. [survival_update](scratches/survival_update/NOTES.md) now has
504/504 instructions, 139/0/0 references, and encoded-body identity. Passing temporary
vectors at both early and later milestone calls recovers the native stack reuse; either
phase alone fails. The centroid and random edge-spawn owners remain unchanged.

It joins [play_game_menu_update](scratches/play_game_menu_update/NOTES.md), whose opening
position and later SDK list-call expression likewise had to change together, plus
player_fire_weapon, demo_trial_overlay_render, and credits_screen_update. Keep this batch
ID reserved for its completed group.

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

Complete. [mods_menu_update](scratches/mods_menu_update/NOTES.md) recovers all 648 instructions,
184 references, and exact encoded bytes through its version-formatting storage. The retained
256-byte buffer shares stack storage with the earlier enumeration record and recovers the native
0x144 frame. Both 256- and 260-byte controls are exact, so the precise original capacity remains
an inference.

[ui_menu_layout_init](scratches/ui_menu_layout_init/NOTES.md) has
1,422/1,422 exact normalized instructions and 538/0/0 references after recovering panel
values, indexed table passes, prompt transforms, and a relative narrow-screen shift. Its
remaining raw-byte differences are equivalent commuted base/index encodings. It joins
quest_select_menu_update, options_menu_update, and perk_selection_screen_update. Use existing
authenticated UI declarations as evidence and keep changes local until a common owner is demonstrated.

<a id="batch-07"></a>

## 07 — UI loops, formatting, and board state

Complete. [statistics_menu_update](scratches/statistics_menu_update/NOTES.md) recovers all
676 instructions, 279 references, and exact encoded bytes. Session and total time share the
hours value; minute conversion retains the original seconds, and the optional F1 readout has
one guarded block. All three ownership/control changes are needed together.

[ui_scrollbar_update](scratches/ui_scrollbar_update/NOTES.md)
recovers exact bytes through geometry/focus ownership, color-before-position construction,
and its row loop. [credits_secret_alien_zookeeper_update](scratches/credits_secret_alien_zookeeper_update/NOTES.md)
recovers exact bytes through shared row/column indices, explicit direction-specific stores,
and both direct button-vector expressions. Use their complete interaction controls as
comparisons for other formatting and rendering lifetimes.

<a id="batch-08"></a>

## 08 — HUD and effect rendering

Two renderers remain after the bonus HUD slot and bonus renderer became byte-exact. Preserve pass
boundaries, direct pool ownership, callback ordering, and rounded x87 intermediates.

[bonus_hud_slot_update_and_render](scratches/bonus_hud_slot_update_and_render/NOTES.md) recovers
405 instructions through temporary position/color arguments, named bar ratios, and a shared
mode join. [bonus_render](scratches/bonus_render/NOTES.md) recovers 1,088 instructions through
bounded player and hover-search loops, an early return after label rendering, and reuse of the
beam phase-size value for its scaled half-height. Their complete interaction controls document
why the individual changes alone do not match.

| Function / detailed evidence | Match | Insns C/N | Gap | Ref mismatches | Evidence |
|---|---:|---:|---:|---:|:---:|
| [ui_render_hud](scratches/ui_render_hud/NOTES.md) | 88.29% | 1823/1824 | 829 | 0 | H |
| [player_render_overlays](scratches/player_render_overlays/NOTES.md) | 87.29% | 1141/1148 | 583 | 0 | H |

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

Two targets remain. [tutorial_timeline_update](scratches/tutorial_timeline_update/NOTES.md) now
has 695 exact instructions, 189 clean references, and encoded-body identity. Its adjacent stage
index/timer tuple, unconditional cap, direct spawn temporaries, and preincrement recover the
native ownership and control flow. For creature rendering or templates, select one pass or
publication sequence using the recorded field and call anchors.

| Function / detailed evidence | Match | Insns C/N | Gap | Ref mismatches | Evidence |
|---|---:|---:|---:|---:|:---:|
| [creature_spawn_template](scratches/creature_spawn_template/NOTES.md) | 88.89% | 3161/3159 | 1,566 | 1 | H |
| [creature_render_type](scratches/creature_render_type/NOTES.md) | 79.74% | 760/765 | 574 | 5 | H |

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
| [projectile_render](scratches/projectile_render/NOTES.md) | 58.55% | 2885/3021 | 5,202 | 10 | H |

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
