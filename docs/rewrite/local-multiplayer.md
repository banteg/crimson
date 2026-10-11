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

Native controls are described in
[local multiplayer controls](../crimsonland-exe/local-multiplayer-controls.md).

## Code

- `src/grim/config.py`: per-player bind blocks and direction-arrow flags in the
  config's ten-slot arrays.
- `src/crimson/input_codes.py`: per-player input queries; edges latch per
  `(player_index, input_code)`.
- `src/crimson/gamepad_profile.py`: the modern controller profile that replaces
  a player's stock bindings when their pad connects.
- `src/crimson/local_input.py`: control scheme plus bind block to `PlayerInput`.
- `src/crimson/screens/panels/controls.py`: player selector and rebinding.
- `src/crimson/quests/results.py`: life bonus over every player's health.
