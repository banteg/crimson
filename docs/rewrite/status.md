# Rewrite status (Python + raylib)

This page is the current snapshot of the **Python + raylib rewrite** under `src/`,
and the **gaps vs the classic Windows build (v1.9.93)** as documented under
`docs/crimsonland-exe/`.

## What you can run today

- `uv run crimson`
  - Full boot flow (splash + company logos) → main menu.
  - Play Game / Options / Statistics panels.
  - Survival / Rush / Quests / Typ-o-Shooter / Tutorial gameplay loops are all wired and playable.
  - Multiplayer (2–4): player count spawns multiple players, but all players currently share the same input (mirrored controls).
  - Game over → high score entry for Survival/Rush/Typ-o; Quest completion/failure routes to results/failed screens.
- Quest results/failed screens (states 8 and 0xc) are fully implemented.
  - Menu idle triggers demo/attract mode.
- `uv run crimson view <name>`: debug views (terrain, atlases, survival, player sandbox, etc).
- `uv run crimson quests <level>`: quest builder output / spawn scripts.

## Coverage map (rewrite vs classic)

### Front-end (menus + screens)

- **Main menu (state `0`)**: implemented (layout/timeline rules, terrain persistence, sign shadow pass).
  - Code: `src/crimson/game.py` (`MenuView`)
  - Ref: `docs/crimsonland-exe/main-menu.md`
- **Play Game panel (state `1`)**: implemented (mode buttons, player-count dropdown, tooltips, F1 “times played” overlay).
  - Code: `src/crimson/game.py` (`PlayGameMenuView`)
  - Ref: `docs/crimsonland-exe/play-game-menu.md`
- **Quest select menu (state `0x0b`)**: UI implemented (stage icons, hardcore toggle gating, quest list + counts overlay).
  - Code: `src/crimson/game.py` (`QuestsMenuView`)
  - Ref: `docs/crimsonland-exe/quest-select-menu.md`
  - Selecting a quest starts Quest gameplay (with results/failed screens).
- **Options panel (state `2`)**: partially implemented.
  - Code: `src/crimson/game.py` (`OptionsMenuView`)
  - Implemented: SFX/music volume sliders, detail preset slider, mouse sensitivity, “UI Info texts”, save-on-exit.
  - Missing: interactive controls rebinding (Controls screen exists but is currently read-only), video/window mode editing, broader parity of widgets/labels.
- **Statistics panel (state `4`)**: partially implemented (Summary/Weapons/Quests pages; reads `game.cfg` counters + checksum).
  - Code: `src/crimson/frontend/panels/stats.py` (`StatisticsMenuView`)
- **Demo / attract mode**: implemented (variant sequencing + upsell + purchase screen flow).
  - Code: `src/crimson/demo.py`
  - Ref: `docs/crimsonland-exe/demo-mode.md`, `docs/crimsonland-exe/screens.md`
  - Demo trial overlay: implemented and wired into gameplay loop.
    - Code: `src/crimson/ui/demo_trial_overlay.py`, `src/crimson/game.py` (`GameLoopView._update_demo_trial_overlay`)
- **Game over / high score entry (state `7`)**: implemented for Survival/Rush/Typ-o.
  - Code: `src/crimson/ui/game_over.py`, `src/crimson/persistence/highscores.py`, `src/crimson/game.py` (`*GameView`)
  - Ref: `docs/crimsonland-exe/screens.md`
  - Gap: UI transition timeline + full UI SFX parity are still missing.
- **Quest results (state `8`) / quest failed (state `0xc`)**: implemented.
  - Code: `src/crimson/game.py` (`QuestResultsView`, `QuestFailedView`)
  - Ref: `docs/crimsonland-exe/screens.md`
- **Mods / Online scores / plugin modal flow**: missing (mods button is a stub; online score submission is not implemented).
  - Ref: `docs/crimsonland-exe/mods.md`, `docs/crimsonland-exe/online-scores.md`, `docs/crimsonland-exe/screens.md`

### Gameplay

- **Core world sim**: `GameWorld` is the active runtime container (players, creatures, projectiles, bonuses/perks, FX queues, terrain renderer).
  - Code: `src/crimson/game_world.py`
- **Survival loop**: wired and playable.
  - Code: `src/crimson/modes/survival_mode.py`, `src/crimson/creatures/spawn.py` (wave + milestone spawns)
  - Gaps: still missing full enemy/weapon parity (remaining per-weapon behaviors), and some SFX/event hooks.
- **Rush / Typ-o-Shooter / Tutorial**: wired and playable.
  - Code: `src/crimson/modes/rush_mode.py`, `src/crimson/modes/typo_mode.py`, `src/crimson/modes/tutorial_mode.py`
  - Tutorial has full stage progression with hint system (`src/crimson/tutorial/timeline.py`).
  - Typ-o-Shooter has typing buffer with target matching and reload command (`src/crimson/typo/typing.py`).
- **Quest mode**: all tiers 1-5 implemented with full spawn scripting.
  - Code: `src/crimson/quests/tier*.py`, `src/crimson/quests/runtime.py`
- **Multiplayer (2–4 players)**: partially wired (player count is read; multiple players spawn).
  - Gap: per-player input is not implemented yet; Survival/Rush/Quest currently feed the same `PlayerInput` to every player (mirrored controls).
  - Code: `src/crimson/modes/base_gameplay_mode.py` (reads `player_count`), `src/crimson/game_world.py` (`reset(... player_count=...)`), `src/crimson/modes/survival_mode.py` (mirrored input list)
- **Progression/unlocks**: quest unlock indices + completion counters are updated on quest completion; mode play counters increment on mode start.
  - Code: `src/crimson/persistence/save_status.py`, `src/crimson/game.py`

### Audio

- **Audio routing system** (`AudioRouter`): routes gameplay events to SFX with per-creature-type death sounds.
  - Code: `src/crimson/audio_router.py`
  - Creature death SFX: zombie, lizard, alien, spider, trooper variants.
  - Hit SFX: bullet hits (multiple variants), beam hits, explosion for rockets.
  - Weapon SFX: fire and reload sounds mapped per-weapon.
  - Survival music trigger: game tune activates on first hits in Survival mode.

### Evidence (what is verified)

- Ground renderer parity is guarded by fixture tests against runtime dumps:
  - Doc: `docs/rewrite/terrain.md`
  - Test: `tests/test_ground_dump_fixtures.py`
- There is broad unit test coverage for deterministic subsystems (spawn plans, timelines, perks, config, etc):
  - Tests: `tests/test_spawn_plan.py`, `tests/test_survival_wave.py`, `tests/test_quest_spawn_timeline.py`, …

## Biggest remaining gaps (vs v1.9.93)

1) **Creature + weapon coverage**
   - Remaining per-weapon behaviors and AI edge cases.
2) **Multiplayer (2–4 players)**
   - Player spawning is wired, but inputs are mirrored (all players share the same input).
3) **UI completeness**
   - Full Options/Controls parity (Controls screen is currently non-interactive).
4) **Progression + stats fidelity**
   - Some `game.cfg` counters and stats screen parity are still incomplete.
5) **Out-of-scope / later**
   - Online scores + mods/plugin interface (tracked in the decompiled docs but not implemented in the rewrite yet).
