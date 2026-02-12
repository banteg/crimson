---
tags:
  - mechanics
  - systems
  - progression
---

# Progression systems

How unlocks and persistent state are exposed to the player.

## XP and level gates

XP required for the next Survival level is:

`1000 + 1000 × level^1.8`

When your XP crosses that threshold, your level increments and a perk pick is added.

Level progression is immediate and checked after kills and reward application.

## Survival-only weapon handouts

In single-player Survival, one-time conditional handout checks can replace your weapon temporarily:

- after `64000 ms`, if you never switched off pistol and the one-shot conditions remain open, you can get [Shrinkifier 5k](../secret-weapons.md).
- after 3 recent deaths around the same area and your health is below `15`, you can get [Blade Gun](../secret-weapons.md).

The replacement is revoked by the internal guard once the conditions are no longer met.

## Perk progression

Perk availability is determined by your level and mode state:

- each level-up adds pending perk choices,
- a pending pick can be selected manually in Survival and during tutorial flow,
- in modes with auto-pick enabled, available perks can be assigned automatically.

## Weapon availability

- Pistol is always available.
- Quest unlock indices grow through quest results and unlock weapon entries.
- Survival always starts with Assault Rifle, Shotgun, and Submachine Gun available.
- Secret Splitter Gun unlock is treated as a separate track at the full unlock threshold.

## Shared state between modes

Progression and save-state fields are saved globally in status, while mode results are written into the relevant run tables.
