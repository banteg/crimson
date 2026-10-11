---
icon: lucide/zap
tags:
  - mechanics
  - modes
  - rush
---

# Rush

Pure reaction mode. You're locked to the Assault Rifle with endless ammo.
No bonuses or perks. Score is survival time.

## Starting conditions

- Weapon: Assault Rifle, always.
- Ammo never runs out.
- Bonuses: off.
- Perks: off.

## Spawning

Every 250 ms, two creatures enter at once, 64 units off the side edges:

- **Right edge**: an alien.
- **Left edge**: a jerky spider, 1.4× faster than the alien.

The two spawn points sweep up and down their edges, up to 256 units either
side of the middle, a quarter-cycle apart. A full sweep takes 6.3 seconds.

In co-op the gap halves to 125 ms.

### Scaling over time

Every creature gets tougher with the clock:

| Stat | Start | Per minute |
| --- | ---: | ---: |
| Health | 10 | +6 |
| Size | 47 | +0.6 |
| Speed (alien) | 2.5 | +0.6 |
| Speed (spider) | 3.5 | +0.84 |
| Contact damage | 4 | — |

## Scoring

Ranked by survival time, to 0.01 s. The score card also shows game time,
most-used weapon, kills and hit %.

## Game over

The run ends once the last player's death animation finishes.
