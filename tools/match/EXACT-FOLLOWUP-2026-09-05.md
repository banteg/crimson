# Exact-match follow-up — 2026-09-05

Two functions now match exactly, taking EXE coverage from **631 to 633/671**. This follow-up
concentrated on interactions between opening values and later UI coordinate lifetimes.

| Function | Before | After | Instructions | Prefix | Clean references |
|---|---:|---:|---|---|---|
| [perk_selection_screen_update](scratches/perk_selection_screen_update/NOTES.md) | 94.59% | 100% | 314/314 | 15 → 314 | 119 → 119 |
| [credits_screen_update](scratches/credits_screen_update/NOTES.md) | 98.90% | 100% | 454/454 | 48 → 454 | 175 → 176 |

Both results have zero unresolved or mismatched aligned references. No compiler, shared header,
reference alias, or matching-scope change was needed.

The perk selection recovery combines early line-height initialization with a short Cancel-button
scope. A panel value sum preserves the opening temporary, and an explicit horizontal-offset scalar
recovers the final load/add order. The Cancel vector reuses storage after line height is dead.

The credits recovery also needs a panel value sum, paired with separate row-hit and Secret-button
coordinates at their respective call sites. Copying the perk screen's horizontal-offset expression
would regress this function, so that part of its source remains unchanged.

These results supersede the earlier broad compiler-residual conclusions in the linked histories.
Several individual changes had already failed; the lifetime interactions explain why those
negative controls did not establish a limit on matching.

## Reproducible controls

Eight complete mutation plans evaluated all 94 controls without errors or truncation. The four
remaining functions below retained their starting sources. The per-function notes and plans record
the rejected routes as well as the successful interactions.

| Function | Controls | Plans |
|---|---:|---|
| [perk_selection_screen_update](scratches/perk_selection_screen_update/NOTES.md) | 24 | [cancel-line-height-interaction](scratches/perk_selection_screen_update/cancel-line-height-interaction-mutations.json), [cancel-panel-temporary-interaction](scratches/perk_selection_screen_update/cancel-panel-temporary-interaction-mutations.json), [cancel-horizontal-offset-ownership](scratches/perk_selection_screen_update/cancel-horizontal-offset-ownership-mutations.json) |
| [credits_screen_update](scratches/credits_screen_update/NOTES.md) | 8 | [panel-row-secret-lifetime-interaction](scratches/credits_screen_update/panel-row-secret-lifetime-interaction-mutations.json) |
| [perk_apply](scratches/perk_apply/NOTES.md) | 17 | [exact-followup-value-interactions](scratches/perk_apply/exact-followup-value-interactions-mutations.json) |
| [play_game_menu_update](scratches/play_game_menu_update/NOTES.md) | 30 | [exact-followup-value-interactions](scratches/play_game_menu_update/exact-followup-value-interactions-mutations.json) |
| [unlocked_perks_database_update](scratches/unlocked_perks_database_update/NOTES.md) | 6 | [exact-followup-value-interactions](scratches/unlocked_perks_database_update/exact-followup-value-interactions-mutations.json) |
| [quest_build_spiders_inc](scratches/quest_build_spiders_inc/NOTES.md) | 9 | [exact-followup-value-interactions](scratches/quest_build_spiders_inc/exact-followup-value-interactions-mutations.json) |

## Source commits

- `e1aa0f734` — exact perk selection value lifetimes.
- `52ed2a9d2` — exact credits coordinate lifetimes.

## Verification

- Compared all 671 EXE manifest entries with the 631-exact starting checkpoint: only the two
  functions above changed, both from WIP to exact; all other metrics and target extents agree.
- Full native EXE audit: ABI, function closure, and game-owned closure passed.
- Native artifact verification: both images current; Grim remains 139/139 exact. Imports,
  excluded functions, and toolchain references remain outside full reference closure.
- Full matching checkpoint: 772/810 exact overall and 810/810 reproducible candidates; zero scope,
  claim, evaluation, metadata, experiment, strict-experiment, or native errors.
- The two matches add 3,204 exact code bytes and 93.38 fuzzy-weighted code bytes. The remaining
  38 EXE functions span 153,591 code bytes and 30,148 rounded fuzzy-gap bytes.
- Source commits passed the relevant commit hooks; final documents pass link, frontier-coverage,
  and whitespace checks.
