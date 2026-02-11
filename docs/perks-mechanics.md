---
tags:
  - gameplay
  - perks
---

# Perks mechanics (version-agnostic)

This page is the player-facing, mechanics-accurate description of perk effects.
It is shared between the original game and the rewrite.

Scope:

- Describe what each perk does in plain technical prose.
- Avoid flavor text and UI copy.
- Keep this version-agnostic; implementation details stay in `docs/perks.md`.

For source-level evidence and parity notes, see:

- [Perks (behavior reference)](perks.md)
- [Perk ID map](perk-id-map.md)
- [Perk matrix (rewrite wiring)](rewrite/perk-matrix.md)

## Conventions

- Numeric values are written exactly when known (timers, multipliers, ranges).
- If behavior is conditional, conditions are stated explicitly.
- If a behavior is known to differ, this document should describe the intended
  shared mechanics and link to the parity note in `docs/perks.md`.

## Mechanics catalog

This catalog will be filled incrementally with structured prose sections per
perk family:

- Survivability and damage mitigation
- Weapon handling and reload modifiers
- Movement and pacing
- XP and progression economy
- Area control, status, and crowd interaction
- High-risk / high-variance perks

Each section should include:

1. What the perk changes in gameplay terms.
2. Exact numeric mechanics.
3. Important interactions and precedence rules.
4. Multiplayer notes when behavior is shared/global.
