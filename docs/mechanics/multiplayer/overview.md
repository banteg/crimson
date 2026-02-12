---
tags:
  - mechanics
  - multiplayer
---

# Local multiplayer

Crimson supports local co-op input in Survival, Rush, and Quest.

## What is shared vs per-player

- Input is now interpreted per-player, using separate bind sets.
- Sim updates still receive a per-player input array to the same world update loop.
- Shared run semantics remain:
  - player 1 owns the run-over/score record flow,
  - player 1 owns perk-pick prompt and opening.

## 3–4 player support details

- `Player 1..4` input binding is supported by `LocalInputInterpreter`.
- The implementation keeps native `1–2 player` behavior intact and extends deterministically for 3–4 players using the same per-player rules.
- Extra player bind data is stored in reserved config slots.

## Gameplay-side effects

- Camera and creature targeting are still driven by the current simulation and shared world state.
- Multiplayer changes in tutorial and Typ-o modes are intentionally not introduced.
- Quest/Survival high-score and perk ownership still resolve to player 0 for score tables and prompt control.
