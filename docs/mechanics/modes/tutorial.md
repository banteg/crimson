---
tags:
  - mechanics
  - modes
  - tutorial
---

# Tutorial

A guided onboarding sequence that teaches movement, shooting, pickups,
and perks through a fixed series of stages. Single-player only. No score
is recorded.

## Starting conditions

- Weapon: Pistol.
- Bonuses: placed by the tutorial script (not random drops). Bonuses
  persist indefinitely until picked up.
- Perks: enabled at stage 6 for the perk lesson.

## Stages

The tutorial advances through 8 stages, each gated by a specific player
action:

| Stage | Instruction | Advances when |
| ---: | --- | --- |
| 1 | Intro text | Play begins |
| 2 | Move with keys | Move key pressed |
| 3 | Pick up bonus | Bonus pool empty |
| 4 | Shoot while moving | Fire key pressed |
| 5 | Aim with mouse | All creatures dead |
| 6 | Perk intro + repeated waves | 7 waves cleared, perk picked |
| 7 | Final wave | All creatures dead |
| 8 | Close-out | Player selects Play or Repeat |

A skip button appears after 1 second on each stage (except stage 8,
which shows Play and Repeat buttons instead).

## Stage 6 bonus rotation

During the 7 repeated waves in stage 6, each wave has a designated
creature that drops a specific bonus on death, cycling through:

1. Speed
2. Weapon
3. Double Experience
4. Nuke
5. Reflex Boost

The cycle repeats from the start for waves 6 and 7.

## Forced state

The tutorial script can force the player's health and experience to
specific values at stage transitions to ensure a consistent teaching
flow.
