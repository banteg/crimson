# Progress metrics

This page tracks progress toward 100% fidelity with the original game.

## Feature parity dashboard

Legend: ✅ complete · 🚧 in progress · ⬜ not started

| Feature | Scoping | Analysis | Validation | Parity | Notes |
|---------|:-------:|:--------:|:----------:|:------:|-------|
| Formats (PAQ/JAZ) | ✅ | ✅ | ✅ | ✅ | Full extraction & conversion pipeline working. |
| Quest Logic | ✅ | ✅ | ✅ | ✅ | All 50 builders dumped, validated, and mirrored in Python. |
| Terrain | ✅ | ✅ | ✅ | 🚧 | Rendering logic validated; baking pipeline in progress. |
| Boot Sequence | ✅ | ✅ | ✅ | 🚧 | Logos, loading steps, and music handoff implemented. |
| Menu System | ✅ | ✅ | 🚧 | ⬜ | State 0 scaffolded; transitions/layout need polish. |
| Weapons | ✅ | ✅ | 🚧 | ⬜ | Table structure known; projectile logic pending. |
| Creatures: structs | ✅ | 🚧 | ⬜ | ⬜ | Creature pool field map is medium-confidence; needs more xrefs + runtime checks. |
| Creatures: spawning | ✅ | 🚧 | ⬜ | ⬜ | Spawn templates are an algorithm (formations/spawn slots/tail mods); plan rewrite started. |
| Creatures: animations | ✅ | 🚧 | ⬜ | ⬜ | Atlas/frame selection understood at a high level; parity tuning in progress. |
| Creatures: AI | ✅ | 🚧 | ⬜ | ⬜ | AI modes partially mapped; needs runtime evidence and edge cases. |
| Creatures: other | ✅ | ⬜ | ⬜ | ⬜ | Attacks, damage/death, loot/bonuses, and audio behaviors still being scoped. |
| Player | ✅ | ✅ | 🚧 | ⬜ | Input & movement mapped; state struct partially validated. |
| Grim2D | ✅ | ✅ | ✅ | ⬜ | Vtable mapped & validated; implementation deferred. |
| Save/Config | ✅ | ✅ | ⬜ | ⬜ | File formats reversed; editor tools built. |

## Status definitions

See [Work status model](work-status.md) for the full lifecycle:

1. **Scoping** — We know it exists; location identified
2. **Analysis** — Static analysis complete; logic mapped in Ghidra
3. **Validation** — Runtime-confirmed via Frida/WinDbg
4. **Parity** — Reimplemented in Python; matches original exactly

## Known behavior deltas

Intentional divergences from the original:

- None recorded yet.
