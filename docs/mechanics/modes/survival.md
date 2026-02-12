---
tags:
  - mechanics
  - modes
  - survival
---

# Survival

Endless mode. Enemies spawn continuously, accelerating over time. The
player levels up from XP, picks perks, and survives as long as possible.
Score is total XP.

## Starting conditions

- Weapon: Pistol.
- Always available: Pistol, Assault Rifle, Shotgun, Submachine Gun.
  Additional weapons come from quest unlock state.
- Bonuses: enabled.
- Perks: enabled, manual selection on level-up.

## XP and leveling

XP required for next level:

`1000 + 1000 × level^1.8`

Each level-up adds one pending perk pick. The perk menu appears while at
least one player is alive and a pick is pending.

## Spawning

### Continuous waves

Spawn cooldown decreases by `player_count × frame_dt` each frame. When
it crosses zero, one creature spawns from a random edge and cooldown
resets to:

`500 − elapsed_ms / 1800` (milliseconds, minimum 1)

If the interval is already negative, extra creatures spawn first, then
the interval stretches by 2 ms per extra spawn to keep spacing stable.

### Milestone waves

At certain player levels, scripted waves spawn immediately:

| Level | XP | Wave |
| ---: | ---: | --- |
| 5 | 13,125 | Two 8-alien rings from left and right |
| 9 | 43,224 | Red boss |
| 11 | 64,095 | 12-spider pack |
| 13 | 88,604 | 4 fast red aliens |
| 15 | 116,619 | 8 spiders, 4 per side |
| 17 | 148,033 | Red ranged spider boss |
| 19 | 182,756 | Splitter spider pack |
| 21 | 220,712 | Two splitter packs from opposite corners |
| 26 | 329,315 | 8 ranged spider bosses, 4 per side |
| 32+ | 484,560 | Shock-capable spider bosses and ranged columns |

## Secret weapon handouts

Two one-time weapon handouts can trigger in single-player Survival. See
[Secret weapons](../secret-weapons.md) for full conditions.

## Scoring

Ranked by highest XP. The end-of-run record includes elapsed time, kills,
shots fired, shots hit, and most used weapon.

## Game over

The run ends when all players are dead and their death timers have
completed.
