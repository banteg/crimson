---
tags:
  - mechanics
  - modes
  - survival
---

# Survival mode

Survival is the open-ended mode: endless enemies, level-ups, and perks.

## Core loop

- The mode updates continuously until every alive player is dead and the death timer has finished.
- During normal play, inputs, simulation, and perk progression are active.
- Game over is delayed by per-player death timers so death animation and timing can complete.

## Spawn model

### Continuous waves

- cooldown reduction includes player count.
- wave interval starts from `500 - elapsed_ms / 1800` milliseconds.
- intervals below zero create extra spawns and then stretch the interval to keep spacing stable.

### Level stages

At certain levels, scripted stage waves are added immediately:

- Level 5: ring wave from left and right.
- Level 9: first red boss.
- Level 11: 12 spider pack.
- Level 13: red-fast alien set.
- Level 15: timer spiders on both sides.
- Level 17: red ranged boss.
- Level 19: splitter pack.
- Level 21: second splitter pack.
- Level 26: dual ranged boss spread.
- Level 32+: harder end-stage pattern.

## Perks and progression

- XP growth drives level-up using the threshold formula in [progression](../systems/progression/intro.md).
- Each level-up can add one pending perk.
- Perk UI appears only while at least one player is still alive.

## Weapon setup and persistence

- Weapon availability is refreshed from quest unlock state.
- Pistol is always available.
- In Survival, Assault Rifle, Shotgun, and Submachine Gun are always present as baseline loadout options.

## HUD and counters

- HUD shows health, active weapon, and XP bar.
- Debug view (when enabled) can show elapsed time, stage, level, and kills.
