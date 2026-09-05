# Batches 01–08 results

Completed on 2026-09-05 against source checkpoint `470d9a4ca`.

**EXE increased from 630 to 631 exact functions out of 671.** All 32 requested functions received
focused probes: one became exact, five improved without metric tradeoffs, and 26 remained unchanged.
The 32 recorded mutation plans evaluated all 151 planned controls without errors or truncation.
These counts exclude preliminary exploratory probes. Grim remains 139/139 exact.

## Retained gains

| Function | Before | After | Instructions C/N, before → after | Prefix | Clean references |
|---|---:|---:|---|---|---|
| [perk_selection_screen_update](scratches/perk_selection_screen_update/NOTES.md) | 87.58% | 94.59% | 314/314 → 314/314 | 0 → 15 | 117 → 119 |
| [highscore_sync_worker](scratches/highscore_sync_worker/NOTES.md) | 67.75% | 77.14% | 517/525 → 525/525 | 26 → 26 | 107 → 119 |
| [quest_build_survival_of_the_fastest](scratches/quest_build_survival_of_the_fastest/NOTES.md) | 76.32% | 79.39% | 228/228 → 228/228 | 5 → 5 | 0 → 0 |
| [ui_scrollbar_update](scratches/ui_scrollbar_update/NOTES.md) | 82.22% | 82.43% | 477/479 → 477/479 | 26 → 26 | 62 → 62 |
| [options_menu_update](scratches/options_menu_update/NOTES.md) | 76.29% | 100.00% | 378/377 → 377/377 | 10 → 377 | 153 → 168 |
| [ui_menu_layout_init](scratches/ui_menu_layout_init/NOTES.md) | 95.19% | 95.69% | 1408/1422 → 1408/1422 | 467 → 467 | 528 → 529 |

The retained changes add 730.61 fuzzy-weighted code bytes. Exact EXE coverage is now
164,032/320,827 code bytes; the remaining 40 functions hold 156,795 code bytes and 30,241 rounded
fuzzy-gap bytes. Fuzzy alignment measures normalized instruction similarity, not executable byte
identity or semantic verification.

The options menu recovery gives each checkbox/slider value its observed lifetime. The changed
local static scope ordinals were checked against emitted COFF symbols and native addresses before
updating their aliases. The final exact result has 377/377 instructions, prefix 377, and 168 clean
references; its previous single mismatched reference is gone. All other retained functions have
zero unresolved or mismatched aligned references, unchanged from their starting baselines.

## Batch coverage

| Batch | Functions probed | Recorded controls | Outcome |
|---|---:|---:|---|
| [01](BATCHES.md#batch-01) | 4 | 20 | Unchanged |
| [02](BATCHES.md#batch-02) | 5 | 25 | 1 WIP improvement |
| [03](BATCHES.md#batch-03) | 2 | 16 | 1 WIP improvement |
| [04](BATCHES.md#batch-04) | 5 | 15 | Unchanged |
| [05](BATCHES.md#batch-05) | 4 | 12 | Unchanged |
| [06](BATCHES.md#batch-06) | 5 | 41 | 1 exact, 2 WIP improvements |
| [07](BATCHES.md#batch-07) | 3 | 10 | 1 WIP improvement |
| [08](BATCHES.md#batch-08) | 4 | 12 | Unchanged |

Each linked mutation plan includes the tested alternatives. Per-function NOTES.md files explain
the hypothesis, rejected tradeoffs, and retained result. Rejected forms bound that route at its
tested baseline; they do not establish a compiler limitation.

| Batch | Function / notes | Reproducible plan | Controls | Result |
|---|---|---|---:|---|
| 01 | [perk_apply](scratches/perk_apply/NOTES.md) | [Plan](scratches/perk_apply/batch-01-focused-value-boundaries-mutations.json) | 5 | Unchanged |
| 01 | [sfx_entry_start_playback](scratches/sfx_entry_start_playback/NOTES.md) | [Plan](scratches/sfx_entry_start_playback/batch-01-focused-value-boundaries-mutations.json) | 5 | Unchanged |
| 01 | [bonus_pick_random_type](scratches/bonus_pick_random_type/NOTES.md) | [Plan](scratches/bonus_pick_random_type/batch-01-focused-value-boundaries-mutations.json) | 4 | Unchanged |
| 01 | [creature_handle_death](scratches/creature_handle_death/NOTES.md) | [Plan](scratches/creature_handle_death/batch-01-focused-value-boundaries-mutations.json) | 6 | Unchanged |
| 02 | [quest_build_spiders_inc](scratches/quest_build_spiders_inc/NOTES.md) | [Plan](scratches/quest_build_spiders_inc/batch-02-focused-value-boundaries-mutations.json) | 5 | Unchanged |
| 02 | [quest_spawn_timeline_update](scratches/quest_spawn_timeline_update/NOTES.md) | [Plan](scratches/quest_spawn_timeline_update/batch-02-focused-value-boundaries-mutations.json) | 4 | Unchanged |
| 02 | [quest_build_survival_of_the_fastest](scratches/quest_build_survival_of_the_fastest/NOTES.md) | [Plan](scratches/quest_build_survival_of_the_fastest/indexed-late-edge-ownership-mutations.json) | 9 | WIP improved |
| 02 | [creature_spawn](scratches/creature_spawn/NOTES.md) | [Plan](scratches/creature_spawn/batch-02-focused-value-boundaries-mutations.json) | 4 | Unchanged |
| 02 | [projectile_spawn](scratches/projectile_spawn/NOTES.md) | [Plan](scratches/projectile_spawn/batch-02-focused-value-boundaries-mutations.json) | 3 | Unchanged |
| 03 | [highscore_sync_worker](scratches/highscore_sync_worker/NOTES.md) | [Plan](scratches/highscore_sync_worker/request-path-publication-mutations.json) | 10 | WIP improved |
| 03 | [statistics_update_check_worker](scratches/statistics_update_check_worker/NOTES.md) | [Plan](scratches/statistics_update_check_worker/batch-03-focused-value-boundaries-mutations.json) | 6 | Unchanged |
| 04 | [player_fire_weapon](scratches/player_fire_weapon/NOTES.md) | [Plan](scratches/player_fire_weapon/batch-04-focused-value-boundaries-mutations.json) | 3 | Unchanged |
| 04 | [survival_update](scratches/survival_update/NOTES.md) | [Plan](scratches/survival_update/batch-04-focused-value-boundaries-mutations.json) | 3 | Unchanged |
| 04 | [play_game_menu_update](scratches/play_game_menu_update/NOTES.md) | [Plan](scratches/play_game_menu_update/batch-04-focused-value-boundaries-mutations.json) | 3 | Unchanged |
| 04 | [credits_screen_update](scratches/credits_screen_update/NOTES.md) | [Plan](scratches/credits_screen_update/batch-04-focused-value-boundaries-mutations.json) | 3 | Unchanged |
| 04 | [demo_trial_overlay_render](scratches/demo_trial_overlay_render/NOTES.md) | [Plan](scratches/demo_trial_overlay_render/batch-04-focused-value-boundaries-mutations.json) | 3 | Unchanged |
| 05 | [unlocked_weapons_database_update](scratches/unlocked_weapons_database_update/NOTES.md) | [Plan](scratches/unlocked_weapons_database_update/batch-05-focused-value-boundaries-mutations.json) | 3 | Unchanged |
| 05 | [unlocked_perks_database_update](scratches/unlocked_perks_database_update/NOTES.md) | [Plan](scratches/unlocked_perks_database_update/batch-05-focused-value-boundaries-mutations.json) | 3 | Unchanged |
| 05 | [ui_cursor_render](scratches/ui_cursor_render/NOTES.md) | [Plan](scratches/ui_cursor_render/batch-05-focused-value-boundaries-mutations.json) | 3 | Unchanged |
| 05 | [ui_element_render](scratches/ui_element_render/NOTES.md) | [Plan](scratches/ui_element_render/batch-05-focused-value-boundaries-mutations.json) | 3 | Unchanged |
| 06 | [perk_selection_screen_update](scratches/perk_selection_screen_update/NOTES.md) | [Plan](scratches/perk_selection_screen_update/choice-line-height-lifetime-mutations.json) | 3 | WIP improved |
| 06 | [mods_menu_update](scratches/mods_menu_update/NOTES.md) | [Plan](scratches/mods_menu_update/batch-06-focused-value-boundaries-mutations.json) | 4 | Unchanged |
| 06 | [quest_select_menu_update](scratches/quest_select_menu_update/NOTES.md) | [Plan](scratches/quest_select_menu_update/batch-06-focused-value-boundaries-mutations.json) | 3 | Unchanged |
| 06 | [options_menu_update](scratches/options_menu_update/NOTES.md) | [Plan](scratches/options_menu_update/checkbox-slider-value-boundaries-mutations.json) | 28 | Exact |
| 06 | [ui_menu_layout_init](scratches/ui_menu_layout_init/NOTES.md) | [Plan](scratches/ui_menu_layout_init/slot31-position-hover-lifetime-mutations.json) | 3 | WIP improved |
| 07 | [ui_scrollbar_update](scratches/ui_scrollbar_update/NOTES.md) | [Plan](scratches/ui_scrollbar_update/row-origin-value-boundary-mutations.json) | 4 | WIP improved |
| 07 | [statistics_menu_update](scratches/statistics_menu_update/NOTES.md) | [Plan](scratches/statistics_menu_update/batch-07-focused-value-boundaries-mutations.json) | 3 | Unchanged |
| 07 | [credits_secret_alien_zookeeper_update](scratches/credits_secret_alien_zookeeper_update/NOTES.md) | [Plan](scratches/credits_secret_alien_zookeeper_update/batch-07-focused-value-boundaries-mutations.json) | 3 | Unchanged |
| 08 | [bonus_hud_slot_update_and_render](scratches/bonus_hud_slot_update_and_render/NOTES.md) | [Plan](scratches/bonus_hud_slot_update_and_render/batch-08-focused-value-boundaries-mutations.json) | 3 | Unchanged |
| 08 | [bonus_render](scratches/bonus_render/NOTES.md) | [Plan](scratches/bonus_render/batch-08-focused-value-boundaries-mutations.json) | 3 | Unchanged |
| 08 | [ui_render_hud](scratches/ui_render_hud/NOTES.md) | [Plan](scratches/ui_render_hud/batch-08-focused-value-boundaries-mutations.json) | 3 | Unchanged |
| 08 | [player_render_overlays](scratches/player_render_overlays/NOTES.md) | [Plan](scratches/player_render_overlays/batch-08-focused-value-boundaries-mutations.json) | 3 | Unchanged |

## Validation and commits

- Native EXE audit: 631 exact / 40 WIP, ABI passed, function and game-owned closure passed.
- Native verification: both images current; function and game-owned closure passed. Import,
  excluded-function, and toolchain references remain explicitly outside full reference closure.
- Full matching checkpoint: 770/810 exact overall, 810/810 reproducible candidates; zero scope,
  claim, evaluation, metadata, experiment, strict-experiment, or native errors.
- Compared all 671 EXE manifest entries with the starting checkpoint: identical membership and
  target extents; exactly the six functions above changed match metrics. No existing exact match
  or other function regressed in ratio, prefix, aligned references, or instruction-count recovery.
- No shared header, scope, native reference catalog, or modern gameplay source changed.

| Commit | Retained change |
|---|---|
| `365b26aed` | Indexed late quest path publication |
| `889faa58f` | Complete request-path initialization before character publication |
| `e541765db` | Exact options menu coordinate lifetimes and verified local static aliases |
| `470d9a4ca` | Perk line height, menu slot publication, and scrollbar row origin lifetimes |

Batches 09–14 were not probed in this campaign. The [remaining function map](BATCHES.md) keeps their
IDs and removes the now-exact options menu from batch 06. Reopen 01–08 with a new bounded hypothesis
or an interaction supported by these results; a completed pass is not a claim that those batches
are fully matched.
