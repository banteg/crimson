# Rewrite status (Python + raylib)

This page is the current snapshot of the **Python + raylib rewrite** under `src/`,
and the **gaps vs the classic Windows build (v1.9.93)** as documented under
`docs/crimsonland-exe/`.

## What you can run today

- `uv run crimson game`
  - Full boot flow (splash + company logos) → main menu.
  - Play Game / Options / Statistics panels.
  - Survival is playable (single-player) with game over → high score entry.
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
  - Gap: selecting a quest goes to a placeholder screen; quest gameplay is not wired.
- **Options panel (state `2`)**: partially implemented.
  - Code: `src/crimson/game.py` (`OptionsMenuView`)
  - Implemented: SFX/music volume sliders, detail preset slider, mouse sensitivity, “UI Info texts”, save-on-exit.
  - Missing: full controls screen, video/window mode editing, broader parity of widgets/labels.
- **Statistics panel (state `3`)**: partially implemented (reads `game.cfg` / checksum / some counters).
  - Code: `src/crimson/game.py` (`StatisticsMenuView`)
- **Demo / attract mode**: implemented (variant sequencing + upsell + purchase screen flow).
  - Code: `src/crimson/demo.py`
  - Ref: `docs/crimsonland-exe/demo-mode.md`, `docs/crimsonland-exe/screens.md`
  - Gap: demo trial overlay is not implemented.
- **Game over / high score entry (state `7`)**: implemented for Survival.
  - Code: `src/crimson/ui/game_over.py`, `src/crimson/highscores.py`, `src/crimson/views/survival.py`
  - Ref: `docs/crimsonland-exe/screens.md`
  - Gaps: high score list screen is missing; some stat fields (shots fired/hit, “most used weapon”) are not tracked yet.
- **Quest results (state `8`) / quest failed (state `0xc`)**: missing.
  - Ref: `docs/crimsonland-exe/screens.md`
- **Mods / Online scores / plugin modal flow**: missing (mods button is a stub; online score submission is not implemented).
  - Ref: `docs/crimsonland-exe/mods.md`, `docs/crimsonland-exe/online-scores.md`, `docs/crimsonland-exe/screens.md`

### Gameplay

- **Core world sim**: `GameWorld` is the active runtime container (players, creatures, projectiles, bonuses/perks, FX queues, terrain renderer).
  - Code: `src/crimson/game_world.py`
- **Survival loop**: wired and playable.
  - Code: `src/crimson/views/survival.py`, `src/crimson/creatures/spawn.py` (wave + milestone spawns)
  - Gaps: still missing full enemy/weapon parity (notably ranged attacks + split-on-death), and many SFX/event hooks.
- **Rush / Typ-o-Shooter / Tutorial**: not wired (UI stubs exist; underlying spawn/timeline logic exists in tests).
  - Code: `src/crimson/game.py` (stubs), `src/crimson/creatures/spawn.py` (rush spawns), `src/crimson/quests/timeline.py` (tutorial/rush timelines)
- **Multiplayer (2–4 players)**: not wired (Play Game panel exposes player count; Survival currently hardcodes `player_count=1`).
  - Code: `src/crimson/views/survival.py`
- **Progression/unlocks**: partially modeled via `game.cfg` and counters, but not fully driven by gameplay outcomes.
  - Code: `src/crimson/save_status.py`, `src/crimson/game.py` (temporary counters on mode start)

### Evidence (what is verified)

- Ground renderer parity is guarded by fixture tests against runtime dumps:
  - Doc: `docs/rewrite/terrain.md`
  - Test: `tests/test_ground_dump_fixtures.py`
- There is broad unit test coverage for deterministic subsystems (spawn plans, timelines, perks, config, etc):
  - Tests: `tests/test_spawn_plan.py`, `tests/test_survival_wave.py`, `tests/test_quest_spawn_timeline.py`, …

## Biggest remaining gaps (vs v1.9.93)

1) **Mode completion parity**
   - Implement Quest/Rush/Typ-o/Tutorial runtime loops (and their results/fail flows).
2) **Progression + persistence parity**
   - Wire quest unlock progression, completion counters, and high-score stat fields (usage + accuracy).
3) **Creature + weapon coverage**
   - Ranged enemies (`CreatureFlags.RANGED_ATTACK_*`), split-on-death, and remaining per-weapon behaviors.
4) **UI completeness**
   - High score list screen, full Options/Controls parity, and demo trial overlay.
5) **Out-of-scope / later**
   - Online scores + mods/plugin interface (tracked in the decompiled docs but not implemented in the rewrite yet).

