---
tags:
  - rewrite
  - parity
---

# Rewrite Parity

Parity status and known behavior deltas.

- [Rewrite status](../status.md)
- [Zig native port status](../zig-verifier.md) - full native-port scope and current mature surfaces
- [Original bugs and rewrite policy](../original-bugs.md)
- [Typ-o-Shooter text input parity](typo-mode-text-input.md)
- [Delta-time parity reference](delta-time.md)
- [Parity audit 2026-06-12](audit-2026-06-12.md) - undocumented divergences found by decompile-vs-port audit

## Known input helper difference

Native `input_primary_is_down` at `0x004460f0` is a pure held-state query that
always checks mouse button 0 and the fire binding in both fixed player records;
the second record also supplies the alternate keyboard binding in one-player
configuration. The Python helper accepts a clamped one-to-four player count,
checks only those supplied fire codes, and updates its shared pressed-state
tracker. This is a port API generalization, not a literal recovery of the
native helper.
