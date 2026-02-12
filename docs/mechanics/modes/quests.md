---
tags:
  - mechanics
  - modes
  - quests
---

# Quest mode

Quest mode runs the scripted build selected in quest menu, with fixed objective flow and completion timing.

## How a run starts

- You pick a quest and it loads terrain plus a spawn script.
- Start weapon comes from the quest definition.
- A timestamped spawn table is built and then consumed over time.

## Spawn behavior

- Each table entry has a trigger time, creature pattern, and count.
- The table clock advances while the run is active.
- When trigger time is reached, all remaining entries for that timestamp spawn.
- If the board goes idle too long, the timer can force a pending trigger to avoid stalls.

Quest entries can be enlarged in hardcore as follows:

- most multi-spawn entries get `+8` extra spawns,
- one special class gets `+2`.

## Completion transition

Run completion needs two things:

- spawn table emptied,
- no living active creatures.

Then the transition waits through a short completion window:

- after about `0.8 s`, quest-hit feedback can fire,
- after about `2 s`, completion music transition can start,
- after about `2.5 s`, the result is finalized.

## Score and outcomes

Quest run records keep:

- elapsed time in milliseconds,
- kills,
- shots fired and hits,
- most used weapon,
- base quest string.

Ranking prefers lower completed time. Unfinished entries are ranked after finished ones.

## Failure behavior

If all players die before completion, the run is marked as failed but still writes a normal outcome record for stats and score tables.
