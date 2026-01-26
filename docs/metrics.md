# Progress metrics

This page tracks progress toward 100% fidelity with the original game.

## Feature parity dashboard

Legend: ✅ complete · 🚧 in progress · ⬜ not started

| Feature | Scoping | Analysis | Validation | Parity | Notes |
|---------|:-------:|:--------:|:----------:|:------:|-------|
| Formats (PAQ/JAZ) | ✅ | ✅ | ✅ | ✅ | Full extraction & conversion pipeline working. |
| Quest Logic | ✅ | ✅ | ✅ | ✅ | All 50 builders dumped, validated, and mirrored in Python. |
| Terrain | ✅ | ✅ | ✅ | 🚧 | Rendering logic validated; decal baking wired into Survival. |
| Boot Sequence | ✅ | ✅ | ✅ | 🚧 | Logos, loading steps, and music handoff implemented. |
| Menu System | ✅ | ✅ | 🚧 | 🚧 | State 0: quit wired; panel/back positions + slide animation match; terrain stable across menu screens; sign shadow pass matches when fx_detail is enabled. |
| Demo / attract loop | ✅ | 🚧 | ⬜ | ⬜ | Variants + spawn ids identified; upsell overlay + purchase screen implemented; sequencing/idle trigger still stubbed. |
| Weapons | ✅ | ✅ | 🚧 | 🚧 | Core weapons (pistol/AR/shotgun/minigun/rocket) use pellet spread + rocket splash; basic fire/reload/hit SFX hooks wired; remaining special weapons pending. |
| Creatures: structs | ✅ | 🚧 | ⬜ | ⬜ | Creature pool field map is medium-confidence; needs more xrefs + runtime checks. |
| Creatures: spawning | ✅ | 🚧 | ⬜ | ⬜ | Spawn templates are an algorithm (formations/spawn slots/tail mods); plan rewrite started. |
| Creatures: animations | ✅ | 🚧 | ⬜ | ⬜ | Atlas/frame selection wired into Survival; parity tuning in progress. |
| Creatures: AI | ✅ | 🚧 | ⬜ | ⬜ | AI modes partially mapped; needs runtime evidence and edge cases. |
| Creatures: other | ✅ | 🚧 | ⬜ | 🚧 | Contact damage/death/bonus hooks live; death SFX hooks wired; ranged attacks + full audio behaviors pending. |
| Player | ✅ | ✅ | 🚧 | ⬜ | Input & movement mapped; state struct partially validated. |
| Grim2D | ✅ | ✅ | ✅ | ⬜ | Vtable mapped & validated; implementation deferred. |
| Save/Config | ✅ | ✅ | ⬜ | ⬜ | File formats reversed; editor tools built. |

## Ghidra maps

<!-- map-progress:start -->
| Map | Total entries | crimsonland.exe | grim.dll | With signatures | With comments | Duplicate names |
| --- | --- | --- | --- | --- | --- | --- |
| Name map | 1167 | 695 | 472 | 1147 | 1144 | 0 |
| Data map | 855 | 754 | 101 | n/a | 855 | 0 |
<!-- map-progress:end -->

### Decompiled data symbol coverage

<!-- data-map-coverage:start -->
| Program | Labeled symbols | Total data symbols | Coverage |
| --- | --- | --- | --- |
| crimsonland.exe | 387 | 2576 | 15.02% |
| grim.dll | 84 | 479 | 17.54% |
| Total | 471 | 3055 | 15.42% |
<!-- data-map-coverage:end -->

## Status definitions

See [Work status model](work-status.md) for the full lifecycle:

1. **Scoping** — We know it exists; location identified
2. **Analysis** — Static analysis complete; logic mapped in Ghidra
3. **Validation** — Runtime-confirmed via Frida/WinDbg
4. **Parity** — Reimplemented in Python; matches original exactly

## Known behavior deltas

Intentional divergences from the original:

- None recorded yet.

## Demo / attract loop tasks (rewrite)

Legend: ✅ complete · 🚧 in progress · ⬜ not started

- ✅ Identify spawn ids used by demo variants (0x24, 0x25, 0x34, 0x35, 0x38, 0x41) and port to spawn-plan rewrite.
- ✅ Fix demo loop sequencing to match `demo_mode_start` (variant index modulo 6, purchase interstitial timing, restart rules).
- ✅ Add menu idle timer trigger (attract starts after inactivity; resets on input).
- ✅ Implement demo upsell overlay (upsell "Want more ..." message + progress bar).
- ⬜ Implement `demo_trial_overlay_render` for demo builds (trial messaging + timing).
- ✅ Implement full `demo_purchase_screen_update` purchase screen UI.
- ✅ Replace DemoView toy simulation with real gameplay systems (creature alloc/update, weapons/projectiles, collision/damage, terrain bounds).
