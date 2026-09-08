# Callback lifecycle ownership follow-up (2026-09-08)

Following the reference/TU audit, 22 additional callback objects provide 80
compiler-local destructor thunks already emitted by their canonical source.
Binding those thunks removes 80 redundant standalone objects: the EXE
selection moves from **650 to 570 objects**, with **671 native functions**
and **28 minimum ownership groups** (previously six).

This records callback/local-static co-residence. It does not recover original
filenames or prove that neighboring callbacks shared a complete original TU.
Canonical per-function scratches remain available as independent baselines.

## Ownership evidence

Every added thunk satisfies all of the following:

- Its callback object defines a static COFF symbol (`storage_class=3`).
- The thunk is one native `ret` instruction and remains encoded-body exact.
- The callback reference audit pairs its local symbol with the exact native
  destructor address at an independently identified registration push.
- Live Binary Ninja disassembly follows that push to `crt_atexit` at
  `0x00460d86`, without an intervening branch or stack operation.
- The TU gate independently rechecks every callback and destructor against
  the selected canonical function, including encoded-body non-regression.

The machine-readable evidence in
`tools/native/translation_units/crimsonland.exe-lifecycle-evidence.json`
contains each source digest, native address, candidate symbol, body result,
reference result, and complete native registration-sequence bytes. The
reference image SHA-256 pins the binary epoch.

| Callback | Local destructors |
|---|---:|
| `credits_screen_update` | 2 |
| `credits_secret_alien_zookeeper_update` | 2 |
| `demo_purchase_screen_update` | 2 |
| `demo_trial_overlay_render` | 3 |
| `game_over_screen_update` | 5 |
| `game_update_victory_screen` | 4 |
| `mod_load_info` | 1 |
| `mods_menu_update` | 3 |
| `options_menu_update` | 6 |
| `perk_selection_screen_update` | 5 |
| `play_game_menu_update` | 7 |
| `quest_failed_screen_update` | 3 |
| `quest_results_screen_update` | 6 |
| `quest_select_menu_update` | 10 |
| `statistics_menu_update` | 8 |
| `tutorial_prompt_dialog` | 2 |
| `typo_gameplay_update_and_render` | 1 |
| `ui_menu_item_update` | 2 |
| `ui_profile_menu_update` | 4 |
| `ui_render_aim_indicators` | 2 |
| `ui_render_hud` | 1 |
| `ui_update_notice_update` | 1 |

## Source experiment

The projectile-render ion clamp sweep completed all 17 combinations. Its
best fuzzy score sacrifices instruction parity, so no gameplay source was
changed. See the target NOTES and recorded mutation plan for that bounded
negative result.

## Tooling correction

The persisted EXE-link test still expected 705 input objects and a fixed
entry-point RVA/image size predating the previous TU recovery. The old
committed link already had 692 inputs. The test now joins the link receipt
with the current object-audit digest, counts declared object/library inputs,
and checks PE format, a valid entry-point range, and page-aligned image size.
It retains the import/provider and zero-retained-placeholder assertions.

## Validation

The independent byte check verifies all 80 saved registration sequences against
the reference PE, re-reads every static COFF symbol and one-byte body, and
confirms all 22 owner object hashes are unchanged from the prior audit.
Every affected function keeps its previous match fields. The only corpus
match change is the separately committed Spiders Inc. improvement (`8f9dbab82`),
which this artifact refresh incorporates.

The full checkpoint passes with zero scope, claim, evaluation, metadata,
experiment, strict-experiment, regression, or native errors. Matching stays at
**793/810 normalized exact** and **791/810 encoded-body exact**.

The structural EXE relink passes with **612 total object/library inputs** and
**zero retained placeholders**. Both images have current audit digests, output
hashes, and provider-evidence hashes. The link receipt proves provider closure;
no runtime gameplay test is claimed.

All **423 matching/native tests** pass against the final relink, including the
corrected persisted-link test. Ruff, the focused type check, and
`git diff --check` pass.

Reproduction:

```sh
.venv/bin/crimson native audit --image crimsonland.exe --require-game-closure -j 8
.venv/bin/crimson native link --image crimsonland.exe -j 8
.venv/bin/crimson match checkpoint --base 8f9dbab82 -j 8
.venv/bin/pytest -q tests/test_match*.py tests/native/test_native_link.py
.venv/bin/crimson native verify --require-game-closure
```

Further ownership recovery needs additional source evidence. Controls still
spells its destructor registrations explicitly, and the console initializer
chain uses external helper declarations. Neither is promoted by this survey of
already-emitted local destructor symbols.
