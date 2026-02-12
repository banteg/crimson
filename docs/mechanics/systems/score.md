---
tags:
  - mechanics
  - systems
  - score
---

# Score and progression counters

This page explains what you can read from the live HUD and what is written on run end.

## Survive mode score

- `experience` is the visible score value.
- It increases from kill rewards and is affected by [Double Experience](../perks.md#37-toxic-avenger).
- The game checks level thresholds against this same counter.

## Timing and ranking data

Each completed run writes a record containing:

- `score_xp`
- elapsed time in milliseconds,
- total kills,
- shot fired and shot hit counters,
- your most used weapon.

## Per-mode leaderboard ranking

- Survival compares higher `score_xp` first.
- Rush compares longer survival time first.
- Quest compares faster completion time first, with unfinished entries sorted behind finished ones.

High score file names are:

- `scores5/survival.hi`
- `scores5/rush.hi`
- `scores5/typo.hi`
- `scores5/quest*.hi` for quest variants.

## Death and retry metrics

Quest and survival run-over screens also include kills and shot counters so you can compare both aggression and efficiency, not just score.
