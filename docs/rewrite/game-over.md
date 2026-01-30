# Game over (rewrite)

This documents the current status of the **Game Over / high score entry** screen in the Python + raylib rewrite and what is still missing for full fidelity.

## What’s implemented

- Survival/Rush/Typ-o death opens the game over UI (banner + name entry + score card + buttons).
- High score records are persisted to the `scores5/` directory using the same byte-wise encoding + checksum scheme as the original.
- The score card renderer ports the decompiled `ui_text_input_render` behavior:
  - Score + Rank column.
  - Game time column with the 32x32 clock gauge and `m:ss` time string.
  - “Most used weapon”, “Frags”, and “Hit %” row is shown only after the name entry phase (suppressed while typing, matching the exe behavior).
  - Hover tooltips for weapon/time/hit ratio (fade-in after ~0.25s hover).

Code pointers:

- `src/crimson/ui/game_over.py` (UI + score card renderer)
- `src/crimson/persistence/highscores.py` (record encode/decode + table insert logic)
- `src/crimson/modes/*` + `src/crimson/game.py` (`*GameView`) (death -> game-over wiring)

## High score files (rewrite behavior)

- Stored under `base_dir/scores5/` (e.g. `artifacts/runtime/scores5/survival.hi`).
- Records are limited to the best 100 entries per mode.

## Known gaps / fidelity issues

1) **High scores list screen**

- Implemented: the “High scores” button opens a dedicated list screen (rewrite equivalent of state `0xe`) and returns back to Game Over / Quest Results.

2) **Missing gameplay stats used by the score card**

The original `highscore_record_init` populates:

- `most_used_weapon_id` from per-weapon usage counters.
- `shots_fired` / `shots_hit` and clamps `shots_hit <= shots_fired`.

The rewrite currently:

- Tracks per-weapon usage counts and populates `most_used_weapon_id` from the most-used weapon.
- Tracks shots fired/hit for Survival/Rush/Quests (projectile-based) and Typ-o Shooter (typing-based).

3) **SFX and transitions are incomplete**

The original flow plays UI SFX (type clicks, confirm, error buzzer) and uses the UI transition timeline (`ui_elements_update_and_render`) to animate screen entry/exit.

The rewrite currently:

- Plays the core UI SFX set used by the flow (type clicks, confirm, error, button clicks, and panel open click).
- Still renders without the original transition animation / exit timeline.

4) **Quest mode uses a dedicated flow**

- Quest completion/failure routes to `QuestResultsView` / `QuestFailedView` (not `GameOverUi`).

## Static references (source of truth)

- `analysis/ghidra/raw/crimsonland.exe_decompiled.c`:
  - `game_over_screen_update @ 0040ffc0`
  - `ui_text_input_render @ 004413a0` (score card renderer)
  - `ui_text_input_update @ 0043ecf0` (input widget behavior)
  - `highscore_rank_index @ 0043b520`
  - `highscore_build_path @ 0043b5b0`
