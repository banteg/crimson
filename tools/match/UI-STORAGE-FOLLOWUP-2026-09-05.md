# UI storage follow-up — 2026-09-05

**mods_menu_update improves from 94.44% to 98.92%.** This continuation produced no additional
exact functions; EXE remains 633/671 exact, with Grim at 139/139.

The seven-function pass evaluated 88 complete controls. Six functions retained their starting
sources. The improvement follows the coordinate-lifetime interactions that recovered the exact
perk selection and credits screens in the [previous follow-up](EXACT-FOLLOWUP-2026-09-05.md).

## Retained mods-menu change

| Metric | Before | After |
|---|---:|---:|
| Normalized alignment | 94.444444% | 98.919753% |
| Candidate/native instructions | 648/648 | 648/648 |
| Exact prefix | 0 | 0 |
| Clean / unresolved / mismatched references | 184/0/0 | 184/0/0 |
| Candidate frame size | 0x160 | 0x154 |
| Native frame size | 0x144 | 0x144 |

A short separator scope, separate Launch coordinates, and a short Main Menu coordinate scope
recover the opening vector, selected-mod rendering, and both button regions. Their interaction
adds 116.67 fuzzy-weighted code bytes without a metric tradeoff. The retained source gain is
committed in `9dd9fab27`; the subsequent evidence commit normalizes its block formatting.

Seven instruction differences remain: the prologue/epilogue frame allocation and five addresses
of the file-enumeration buffer. The remaining 16-byte frame difference is an unresolved storage
question. Narrow enumeration scopes, buffer declaration placement, and inlined enumeration/version
helpers do not change it. No buffer size, padding, forced address, union, or compiler option was
changed to manufacture the layout.

## Reproducible controls

Every plan below evaluated all planned variants without compiler errors or truncation. The notes
record each bounded hypothesis and rejected result; these are not impossibility claims.

| Function | Controls | Result | Plan |
|---|---:|---|---|
| [mods_menu_update](scratches/mods_menu_update/NOTES.md) | 28 | Improved | [Controls](scratches/mods_menu_update/separator-button-storage-interactions-mutations.json) |
| [survival_update](scratches/survival_update/NOTES.md) | 16 | Unchanged | [Controls](scratches/survival_update/ui-storage-followup-controls-mutations.json) |
| [demo_trial_overlay_render](scratches/demo_trial_overlay_render/NOTES.md) | 24 | Unchanged | [Controls](scratches/demo_trial_overlay_render/ui-storage-followup-controls-mutations.json) |
| [unlocked_perks_database_update](scratches/unlocked_perks_database_update/NOTES.md) | 2 | Unchanged | [Controls](scratches/unlocked_perks_database_update/ui-storage-followup-controls-mutations.json) |
| [player_fire_weapon](scratches/player_fire_weapon/NOTES.md) | 5 | Unchanged | [Controls](scratches/player_fire_weapon/ui-storage-followup-controls-mutations.json) |
| [quest_select_menu_update](scratches/quest_select_menu_update/NOTES.md) | 6 | Unchanged | [Controls](scratches/quest_select_menu_update/ui-storage-followup-controls-mutations.json) |
| [perk_apply](scratches/perk_apply/NOTES.md) | 7 | Unchanged | [Controls](scratches/perk_apply/ui-storage-followup-controls-mutations.json) |

## Verification

- Native audit and artifact verification: both images current, ABI passed, and function/game-owned
  closure passed. Imports, excluded functions, and toolchain references remain outside full closure.
- Full checkpoint: 772/810 exact overall and 810/810 reproducible candidates; zero scope, claim,
  evaluation, metadata, experiment, strict-experiment, or native errors.
- Compared all 671 EXE manifest entries with the starting checkpoint: only mods_menu_update changed
  matching metrics; its alignment improved and its instruction, prefix, and reference metrics did
  not regress. Every existing exact match is preserved, and all target extents are unchanged.
- The remaining 38 functions hold 30,031 rounded fuzzy-gap bytes, down from 30,148.
- Relevant commit hooks and whitespace checks passed; the remaining-function map covers each WIP
  exactly once and its current metrics and local links were checked.

Source gain: `9dd9fab27`. Complete control evidence and final source formatting: `5ab2935e2`.
