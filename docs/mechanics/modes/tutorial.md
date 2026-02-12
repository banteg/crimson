---
tags:
  - mechanics
  - modes
  - tutorial
---

# Tutorial mode

The tutorial is a staged script that advances by behavior checks, not a freeform challenge.

## Stage progression

The tutorial runs through a fixed sequence of prompts:

1. intro text,
2. move-with-keys check,
3. pickup check,
4. shoot while moving,
5. aim with mouse,
6. perk intro and repeat spawn loop,
7. perk done and final wave,
8. close-out.

## Progress gates

Each stage advances only when its trigger condition is satisfied:

- move key pressed,
- bonus pickup pool is empty,
- fire key pressed,
- all creatures are dead where required,
- perk pending count is handled for the perk lesson.

## Stage 5 repeated loop

After the first clear, the script repeats a wave pattern and carries a counter.

- it runs for the first `7` repeats,
- each repeat can configure a new bonus-carrier,
- the configured bonuses rotate as:
  - speed,
  - weapon,
  - double experience,
  - nuke,
  - reflex boost.

## Script timing

If a stage fails to advance in time, the tutorial keeps prompting the current instruction and can fade text in and out based on stage transitions.

## Why it feels deterministic

The sequence is deterministic from input and state checks, which is why this mode is ideal for first-run onboarding and parity replay work.
