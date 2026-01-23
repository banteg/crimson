---
tags:
  - status-analysis
---

# Runtime structs

This section documents the main runtime data structures used by `crimsonland.exe`.

## Entity pools

- [Player](player.md) — Per-player state (health, position, input bindings)
- [Creature](../creatures/struct.md) — Enemy pool (0x180 entries, 0x98 bytes each)
- [Projectile](projectile.md) — Projectile pool (0x60 entries, 0x40 bytes each)
- [Effects](effects.md) — Particle, blood, and gib pools
