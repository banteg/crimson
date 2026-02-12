---
tags:
  - mechanics
  - systems
  - spawning
---

# Creature spawning and flow

This section is how enemies enter the arena in each mode.

## Survival

### Wave spawn cooldown

Every update, cooldown is reduced by `frame_dt_ms × player_count`.

When cooldown reaches `-1` or below, the game adds a new wave cooldown and spawns one enemy.

The next wave interval starts from:

- `500 - elapsed_ms / 1800` (in milliseconds).

If that interval is already `0` or negative, the game first spawns extra enemies, then stretches the interval back up by `2` for every extra spawn.

## Survival progression stages

At specific player levels, a scripted wave is added immediately:

- Level 5: two 8-alien rings.
- Level 9: one red boss.
- Level 11: 12 two-spider pack.
- Level 13: 4 fast red aliens.
- Level 15: 8 timer-based spiders, 4 on each side.
- Level 17: red ranged spider boss.
- Level 19: splitter spider spawns twice.
- Level 21: two splitters from upper-left and lower-right.
- Level 26: 8 ranged spider bosses, 4 each side.
- Level 32+: two shock-capable spider bosses and two ranged spawn columns.

## Rush

Rush uses two spawns every wave event:

- one from the right side, one from the left side.
- both are paced from the same `250 ms` base cooldown.
- both share the same timer, and it is also sped up by player count as in Survival.

As time passes:

- health slowly increases from `10` plus `0.0001 × elapsed_ms`.
- size slowly increases from `47` plus `0.00001 × elapsed_ms`.
- movement speed on the right start is `2.5 + 0.00001 × elapsed_ms`.
- movement speed on the left is `1.4 ×` the right-side speed.

## Quest

Quest uses a trigger table created from the selected quest. In each update:

- a timeline counter grows with game time,
- entries whose `trigger_ms` has passed are fired,
- each entry can spawn multiple creatures in a line using fixed spacing.

If the table is empty and there have been no active creatures for a while, the timer pauses while waiting to finish the quest-complete transition.

Hardcore quests expand most multi-spawn entries (`+8` extra, `+2` for one special entry) when the spawn table is built.

## Typ-o-Shooter

Typ-o-Shooter uses its own spawn system:

- cooldown decreases by `frame_dt × player_count`.
- while cooldown is negative it repeatedly schedules another pair of tinted spawns.
- cooldown reset amount is `3500 - elapsed_ms / 800`, clamped to `100 ms` minimum.
- each cycle spawns one alien and one spider from opposite edges.

## What affects spawn rate

Spawn cooldown math uses the active player count from current local session, so 2+ player runs naturally scale pacing up faster.
