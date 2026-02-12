---
tags:
  - mechanics
  - modes
  - quests
---

# Quest

Scripted encounters with a fixed spawn timeline. The player clears all
enemies to complete the quest.

## Starting conditions

- Weapon: defined per quest.
- Bonuses: enabled, with stage-specific suppression (see
  [Bonuses — suppression rules](../systems/bonuses.md#suppression-rules)).
- Perks: enabled, manual selection on level-up.
- Terrain: defined per quest.

## Spawning

Each quest has a spawn table of timed entries. A timeline counter
advances with game time, and entries fire when their trigger time is
reached. Each entry can spawn one or more creatures in a formation with
fixed spacing.

If no living creatures remain and the spawn table still has entries, the
timeline keeps advancing. If the table has entries but no creatures have
been active for over 3 seconds (and timeline > ~1700 ms), the next entry
is force-triggered to prevent stalls.

### Hardcore scaling

On hardcore difficulty, most multi-spawn entries get +8 extra creatures.
One special entry class gets +2.

## Completion

A quest is complete when both conditions are met:

1. Spawn table is empty.
2. No living creatures remain.

The completion transition takes about 2.5 seconds: feedback sound at
~0.8 s, music transition at ~2 s, result finalized at ~2.5 s.

## Failure

If all players die before completion, the run is marked as failed. A
record is still written for stats and score tables.

## Scoring

Ranked by fastest completion time. Failed attempts are ranked behind
completed ones. The record includes elapsed time, kills, shots
fired/hit, and most used weapon.
