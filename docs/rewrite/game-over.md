# Game over (rewrite)

This documents the current status of the **Game Over / high score entry** screen in the Python + raylib rewrite and what is still missing for full fidelity.

## What’s implemented

- Survival death opens the game over UI (banner + name entry + score card + buttons) on top of the frozen gameplay scene.
- High score records are persisted to the `scores5/` directory using the same byte-wise encoding + checksum scheme as the original.
- The score card renderer ports the decompiled `ui_text_input_render` behavior:
  - Score + Rank column.
  - Game time column with the 32x32 clock gauge and `m:ss` time string.
  - “Most used weapon”, “Frags”, and “Hit %” row is shown only after the name entry phase (suppressed while typing, matching the exe behavior).
  - Hover tooltips for weapon/time/hit ratio (fade-in after ~0.25s hover).

Code pointers:

- `src/crimson/ui/game_over.py` (UI + score card renderer)
- `src/crimson/highscores.py` (record encode/decode + table insert logic)
- `src/crimson/views/survival.py` (death -> game-over wiring)

## High score files (rewrite behavior)

- Stored under `base_dir/scores5/` (e.g. `artifacts/runtime/scores5/survival.hi`).
- Records are limited to the best 100 entries per mode.

## Known gaps / fidelity issues

1) **High scores list screen is not implemented**

- The “High scores” button currently routes back to the main menu.
- Original behavior transitions to the high score list screen (state `0xe`).

2) **Missing gameplay stats used by the score card**

The original `highscore_record_init` populates:

- `most_used_weapon_id` from per-weapon usage counters.
- `shots_fired` / `shots_hit` and clamps `shots_hit <= shots_fired`.

The rewrite currently:

- Uses the current `player.weapon_id` as “most used weapon”.
- Does not track shots fired/hit yet (hit % will stay at 0).

3) **SFX and transitions are incomplete**

The original flow plays UI SFX (type clicks, confirm, error buzzer) and uses the UI transition timeline (`ui_elements_update_and_render`) to animate screen entry/exit.

The rewrite currently:

- Renders without the original transition animation.
- Does not reproduce the full set of game-over UI SFX.

4) **Quest/Rush variants are not wired**

- Quest failed / quest results / “Well done trooper!” flows are not implemented yet.
- Rush and Quest mode loops are not wired in the rewrite, so their score semantics aren’t exercised.

## Static references (source of truth)

- `analysis/ghidra/raw/crimsonland.exe_decompiled.c`:
  - `game_over_screen_update @ 0040ffc0`
  - `ui_text_input_render @ 004413a0` (score card renderer)
  - `ui_text_input_update @ 0043ecf0` (input widget behavior)
  - `highscore_rank_index @ 0043b520`
  - `highscore_build_path @ 0043b5b0`

