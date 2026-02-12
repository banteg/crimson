---
tags:
  - mechanics
  - modes
  - rush
---

# Rush mode

Rush is pressure mode: constant flow, fixed weapon identity, and score by survival time.

## Flow and pacing

- Spawn timer ticks down with player-count scaling.
- On each wave event the mode spawns two enemies, one from each side.
- Base tick interval is `250 ms`.
- Interval is effectively reduced by how many players are active.

Because this mode is built for reaction speed, it also

- forces [Assault Rifle](../weapons.md#13-assault-rifle),
- keeps your ammo topped up at the end of each frame.

## Bonuses and perks

- Bonuses are disabled in this mode.
- Perk progression is not offered while the rush session runs.
- The perk menu is still available during setup states, but not as Survival-style progression flow.

## Game over and score

- Rush does not show XP scoring the way Survival does.
- Run end is tied to all players being dead.
- Ranking uses longest survival time.

## What to expect visually

- Right-side enemies are the standard alien type,
- left-side enemies are a faster spider-like type,
- both are visible from the edges and quickly accelerate inward.
