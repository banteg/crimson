---
tags:
  - status-analysis
---

# Spawn plan (pure porting model)

The native function `creature_spawn_template` (`0x00430af0`) is an **algorithm**, not a static table:
it allocates creatures, may allocate spawn slots, and applies shared tail modifiers (difficulty, hardcore,
demo gating, etc). See `docs/creatures/spawning.md` for the decompile-facing overview.

This page documents the rewrite’s **pure plan** representation that we use to port and test spawn templates
without needing the realtime creature pool.

**Source of truth:** decompiles. `src/` is the reimplementation, but plan shape and tests are designed to
track `creature_spawn_template` behavior as closely as possible.

## What is a “spawn plan”?

In the rewrite, `build_spawn_plan(...)` (in `src/crimson/creatures/spawn.py`) is a pure function that
models a single call to `creature_spawn_template(template_id, pos, heading)` and returns a `SpawnPlan`
containing:

- `creatures`: every creature allocated/configured by the template (including formations/escorts).
- `spawn_slots`: any spawn-slot entries allocated by the template (deferred child spawns).
- `effects`: side-effects the template triggers (e.g. burst FX when not demo-gated).
- `primary`: index of the “primary” creature in `creatures` (what the native function returns).

The runtime layer can then “materialize” the plan into the realtime pools.

## “Ported” vs “Verified”

We track spawn-template rewrite coverage in `docs/creatures/spawning.md`.

- **Ported** means:
  - `build_spawn_plan` supports the template id and produces a plausible plan shape (creature fields,
    formations, spawn slots, and tail modifiers) derived from decompilation.

- **Verified** means:
  - there is a unit test asserting the resulting plan for that template (fields, counts, and/or
    deterministic MSVCRT RNG consumption).

Tests live in:

- `tests/test_spawn_plan.py` (template plan assertions)
- `tests/test_spawn_slots.py` (spawn-slot tick semantics used by `creature_update_all`)

## Spawn slots in the plan

Some templates allocate a **spawn slot**: a small record that periodically spawns child templates while
the owning creature stays alive.

Native representation (high level; see `docs/creatures/struct.md`):

- Spawn-slot fields live in parallel global arrays (`*_owner`, `*_timer`, `*_interval`, `*_count`, `*_limit`, `*_template`).
- The owning creature stores the slot index in `creature_link_index`.
- The same flag bit (`0x4`) is overloaded:
  - animation short-strip selection, and
  - “this creature’s link_index is a spawn-slot index”.

Plan representation:

- `SpawnPlan.spawn_slots` contains `SpawnSlotInit` records:
  - `owner_creature`: index into `SpawnPlan.creatures`
  - `timer`, `interval`
  - `count`, `limit`
  - `child_template_id`
- The owning `CreatureInit` has `spawn_slot=<index>` populated to link back to the slot.

Spawn-slot ticking is modeled by `tick_spawn_slot(...)` and is deliberately **non-looping** on large `dt`
(matches native behavior).

## Practical workflow

When porting templates:

1) Update/extend the plan builder for the template id.
2) Add or adjust a unit test that asserts the plan output.
3) Regenerate/refresh the status table in `docs/creatures/spawning.md` via the generator script
   referenced in that page.

