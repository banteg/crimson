---
tags:
  - rewrite
---

# Local multiplayer rewrite notes

## Extension policy

- `1–2 players`: preserve native behavior and data layout.
- `3–4 players`: deterministic extension using the same per-player rules.
- Keep native player-0 ownership semantics for shared flows:
  - game-over highscore record source
  - perk pick prompt/input ownership

## Implemented wiring

- Config persistence:
  - P1-P4 keybind blocks use source-defined `input_config[0..3]`; the on-disk array has ten slots.
  - per-player HUD direction-arrow toggles use source-defined `direction_arrow_flags[0..3]`; that array also has ten slots.
  - Code: `src/grim/config.py`
- Input backend:
  - per-player `is_down`/`is_pressed` and axis reads (keyboard/mouse/joy/RIM code families).
  - frame-latched edge semantics are keyed by `(player_index, input_code)`.
  - Code: `src/crimson/input_codes.py`
- Control-scheme interpretation:
  - per-player conversion from controls profile + bind block to `PlayerInput`.
  - supports native mode IDs for move/aim schemes.
  - Code: `src/crimson/local_input.py`
- Gameplay mode wiring:
  - Survival/Rush/Quest now feed per-player input lists (not mirrored player-0 input).
  - Tutorial/Typ-o remain single-player.
  - Code: `src/crimson/modes/survival_mode.py`, `src/crimson/modes/rush_mode.py`, `src/crimson/modes/quest_mode.py`
- Controls UI:
  - player selector supports players `1..4`.
  - per-slot rebind capture supports cancel/default/unbind flows.
  - writes route to per-player persisted blocks (or legacy global slots where applicable).
  - Code: `src/crimson/screens/panels/controls.py`
- Quest results:
  - life bonus aggregation supports N-player health values for 3/4-player runs.
  - 1/2-player scoring behavior is preserved.
  - Code: `src/crimson/quests/results.py`, `src/crimson/game/__init__.py`, `src/crimson/modes/quest_mode.py`
