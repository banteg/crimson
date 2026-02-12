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
- Perks: enabled at the perk lesson stage.

## Stages

The tutorial advances through 9 stages (0-8), each gated by a specific
player action:

| Stage | Instruction | Advances when |
| ---: | --- | --- |
| 0 | Intro text | 6 seconds elapse |
| 1 | Move with arrow keys | Move key pressed |
| 2 | Pick up bonuses | All bonuses collected |
| 3 | Shoot with left mouse | Fire button pressed |
| 4 | Aim at creatures | All creatures killed |
| 5 | Move and shoot together | 7 waves cleared |
| 6 | Learn about perks | Perk picked |
| 7 | Perks give abilities | All creatures and bonuses cleared |
| 8 | Ready to play | Player selects Play or Repeat |

A skip button appears after 1 second on each stage (except stage 8,
which shows Play and Repeat buttons instead).

## Stage 5 bonus rotation

During the 7 combat waves in stage 5, creatures spawn from alternating
sides. The first 5 waves include a bonus carrier creature that drops a
specific bonus on death:

1. Speed
2. Weapon (Shotgun)
3. Double Experience
4. Nuke
5. Reflex Boost

Waves 6 and 7 have no bonus carrier. After each bonus is picked up, a
hint panel describes what it does.

## Forced state

The player's health is locked to 100 throughout the tutorial. Experience
is forced to 0 outside the perk lesson. At the transition from stage 5
to 6, experience is set to 3000 to trigger a level-up and perk choice.
