---
tags:
  - mechanics
  - modes
  - typo
  - typing
---

# Typ-o-Shooter

Typ-o-Shooter replaces shooting by matching names.

## Spawn system

- Every frame, spawn cooldown shrinks by `frame_dt × player_count`.
- When enough time accumulates, it schedules another pair of creatures and resets with:
  - `3500 - elapsed_ms / 800`
  - clamped to `100 ms` minimum.
- Spawns always come in symmetric pairs from opposite sides.
- Each cycle has a cyan-then-green tint progression tied to game time.

## Typing input flow

- Typing characters append to a buffer and play key sounds.
- Enter tries to match a living creature name.
  - when matched, that target is fired at directly.
  - reload key can also be sent from Enter input.
- Backspace edits buffer text.
- Mouse cursor still controls aiming anchor and aim panel still shows.

## Player setup each frame

Typ-o mode forcibly keeps the same constrained state every frame:

- weapon is fixed to the typing rifle,
- shot cooldown is zeroed,
- spread is reset,
- ammo is full,
- reload is inactive.

It also cancels active reactive buffs:

- [Weapon Power Up](../systems/bonuses.md#weapon-power-up),
- [Reflex Boost](../systems/bonuses.md#reflex-boost),
- and clears bonus items pending spawn.

## Game over and scoring

Run over follows the same animation timing as other modes: you get a small delay after death before the screen opens.

High score output uses elapsed time and shot counters from typing actions.
