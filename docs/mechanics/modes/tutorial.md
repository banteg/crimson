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

The tutorial advances through 9 stages. An intro message displays for 6
seconds, then the player learns movement (press a movement key), bonus
pickup (collect placed bonuses), shooting (press fire), and aiming (kill
the spawned creatures). Stage 5 runs 7 combat waves from alternating
sides. After the waves, experience is set to 3000 to trigger a level-up
and perk selection. A final wave follows, then the player chooses Play
or Repeat.

A skip button appears after 1 second on each stage except the last,
which shows Play and Repeat buttons instead.

## Bonus rotation

During the 7 combat waves, creatures spawn from alternating sides. The
first 5 waves include a bonus carrier creature that drops a specific
bonus on death:

1. Speed
2. Weapon (Shotgun)
3. Double Experience
4. Nuke
5. Reflex Boost

Waves 6 and 7 have no bonus carrier. After each bonus is picked up, a
hint panel describes what it does.

## Forced state

The player's health is locked to 100 throughout the tutorial. Experience
is forced to 0 outside the perk lesson.
