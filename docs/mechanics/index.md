---
tags:
  - mechanics
  - audience-design
---

# Mechanics

Canonical gameplay behavior, written as the source of truth for how Crimsonland actually plays.

This section avoids rewrite internals and decompiler implementation details where possible.

## Subsections

- [Combat](combat/index.md) — combat flow and combat systems for player actions.
- Modes — [Survival](modes/survival.md), [Rush](modes/rush.md), [Quests](modes/quests.md), [Typ-o-Shooter](modes/typo-shooter.md), [Tutorial](modes/tutorial.md).
- [Systems](systems/index.md) — gameplay systems like perks and secret weapons.
- [Multiplayer](multiplayer/overview.md) — local multiplayer behavior and split-screen edge cases.
- [Gameplay quirks](quirks/index.md) — notable edge cases and observed behavior oddities.
- [Secret weapons](secret-weapons.md) — hidden weapons outside normal quest progression.

## Related sections

- [Rewrite](../rewrite/index.md) — implementation details and contracts.
- [Reverse engineering](../re/index.md) — static/runtime evidence.
- [Static reference tables](../re/static/reference/index.md) — IDs, tables, and data maps.
- [Verification](../verification/index.md) — parity and differential testing links.
