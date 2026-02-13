---
tags:
  - status-analysis
---

# Secrets and unlocks

This section tracks hidden unlock conditions, Easter eggs, and secret weapon candidates.

## Overview

Crimsonland contains several layers of secrets:

1. **Credits click puzzle** — Clicking lines containing "o" in the credits unlocks the Secret Path
2. **AlienZooKeeper minigame** — A match-3 game accessed via the Secret button
3. **Cryptic messages** — Decoded hints pointing to unknown in-game actions
4. **Secret weapons** — Weapons not unlocked through normal quest progression
5. **Statistics date gate** — March-3 randomized text easter egg (`Orbes Volantes Exstare`)
6. **Startup date gate** — Date-based `balloon.tga` preload path in startup prelude

## Documents

- [Easter eggs](easter-eggs.md) — Credits puzzle, AlienZooKeeper, decoded messages
- [Weapon candidates](weapon-candidates.md) — Data analysis of weapons missing from quest unlocks
- [Survival weapon handouts](survival-weapon-handouts.md) — one-off Survival grants for Shrinkifier 5k and Blade Gun

## Current status

- Credits puzzle logic is fully mapped (click 'o' lines, avoid others)
- AlienZooKeeper minigame code is understood but has no external unlock
- The decoded "Dead Center...Sacrifice...Firepower" line is now best-mapped
  (inference) to the Blade Gun Survival handout gate; no direct string->logic
  xref is known yet
- The March-3 statistics text gate (`stats_menu_easter_egg_roll`) is mapped in decompile.
- The startup date-gated `balloon.tga` path is mapped as a startup-preload-only gate (no in-binary consumer xrefs in v1.9.93).
- 17 named weapons are not in the quest unlock table
- Survival has two verified one-off secret-weapon style grants (Shrinkifier 5k and Blade Gun), with strict runtime gates
