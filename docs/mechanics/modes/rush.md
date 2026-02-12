---
tags:
  - mechanics
  - modes
  - rush
---

# Rush

Pure reaction mode. The player is locked to the Assault Rifle with
infinite ammo. No bonuses, no perks, no pickups. Score is survival time.

## Starting conditions

- Weapon: Assault Rifle (forced). Cannot be changed.
- Ammo is refilled to full clip every frame.
- Bonuses: disabled.
- Perks: disabled.

## Spawning

Every 250 ms, two creatures spawn simultaneously:

- **Right edge**: Alien (type 2).
- **Left edge**: Spider (type 3), 1.4× faster than the right-side alien.

Both spawn positions oscillate vertically using sine/cosine of elapsed
time.

Spawn cooldown decreases by `player_count × frame_dt`, so multiplayer
speeds up the pace.

### Scaling over time

All creatures scale with elapsed time:

| Stat | Formula |
| --- | --- |
| Health | `10 + elapsed_ms × 0.0001` |
| Size | `47 + elapsed_ms × 0.00001` |
| Move speed (right) | `2.5 + elapsed_ms × 0.00001` |
| Move speed (left) | right speed × 1.4 |
| Contact damage | 4.0 (fixed) |

## Scoring

Ranked by longest survival time. The end-of-run record includes kills.

## Game over

The run ends when all players are dead.
